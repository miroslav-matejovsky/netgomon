//go:build windows

package rawsec

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	rawetw "github.com/0xrawsec/golang-etw/etw"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
)

const toolName = "rawsec"

// engineStats tracks diagnostic counters for ETW event processing.
type engineStats struct {
	totalEvents   atomic.Uint64
	mappedEvents  atomic.Uint64
	pidMatches    atomic.Uint64
	parseFailures atomic.Uint64
	eventIDCounts sync.Map // map[uint16]uint64
}

func (s *engineStats) incEventID(id uint16) {
	val, _ := s.eventIDCounts.LoadOrStore(id, new(atomic.Uint64))
	val.(*atomic.Uint64).Add(1)
}

// Engine implements etw.Engine using the 0xrawsec/golang-etw library.
type Engine struct {
	targetPID uint32
	session   *rawetw.RealTimeSession
	consumer  *rawetw.Consumer
	events    chan etwapi.NetworkEvent
	ctx       context.Context
	cancel    context.CancelFunc
	logger    *slog.Logger
	stats     engineStats
}

// New creates a rawsec ETW engine for the given target PID.
func New(ctx context.Context, targetPID uint32, logger *slog.Logger) *Engine {
	ctx, cancel := context.WithCancel(ctx)
	return &Engine{
		targetPID: targetPID,
		events:    make(chan etwapi.NetworkEvent, 256),
		ctx:       ctx,
		cancel:    cancel,
		logger:    logger,
	}
}

// Events returns the channel of captured network events.
func (e *Engine) Events() <-chan etwapi.NetworkEvent {
	return e.events
}

// Start initializes the ETW session and begins consuming events.
func (e *Engine) Start() error {
	sessionName := fmt.Sprintf("NetWinMon_rawsec_%d_%d", e.targetPID, time.Now().Unix())
	e.session = rawetw.NewRealTimeSession(sessionName)

	// stop any pre-existing session with same name
	_ = e.session.Stop()

	if err := e.session.Start(); err != nil {
		return fmt.Errorf("rawsec: failed to start ETW session: %w", err)
	}

	provider, err := rawetw.ParseProvider("Microsoft-Windows-Kernel-Network")
	if err != nil {
		_ = e.session.Stop()
		return fmt.Errorf("rawsec: failed to parse provider: %w", err)
	}
	provider.MatchAnyKeyword = 0xFFFFFFFFFFFFFFFF
	provider.EnableLevel = 5

	if err := e.session.EnableProvider(provider); err != nil {
		_ = e.session.Stop()
		return fmt.Errorf("rawsec: failed to enable provider: %w", err)
	}

	e.consumer = rawetw.NewRealTimeConsumer(e.ctx)
	e.consumer.FromSessions(e.session)

	e.consumer.EventCallback = func(event *rawetw.Event) error {
		return e.processEvent(event)
	}

	go func() {
		_ = e.consumer.Start()
		close(e.events)
	}()

	e.logger.Info("rawsec: ETW session started", "pid", e.targetPID)
	return nil
}

func (e *Engine) processEvent(event *rawetw.Event) error {
	total := e.stats.totalEvents.Add(1)
	e.stats.incEventID(event.System.EventID)

	// Extract PID using case-insensitive matching.
	actualPID := etwapi.FindPIDInMap(event.EventData)
	pidSource := "eventdata"
	if actualPID == 0 {
		actualPID = event.System.Execution.ProcessID
		pidSource = "execution"
	}

	// Log first 20 events for diagnostics.
	if total <= 20 {
		e.logger.Info("rawsec: event sample",
			"event_id", event.System.EventID,
			"exec_pid", event.System.Execution.ProcessID,
			"data_pid", actualPID,
			"pid_source", pidSource,
			"keys", getKeysRaw(event.EventData))
	}

	if actualPID != e.targetPID {
		return nil
	}

	e.stats.pidMatches.Add(1)
	matchCount := e.stats.pidMatches.Load()

	mapping := etwapi.MapEventID(event.System.EventID)
	if mapping == nil {
		e.logger.Debug("rawsec: unmapped event for target PID",
			"event_id", event.System.EventID,
			"pid", actualPID)
		return nil
	}

	e.stats.mappedEvents.Add(1)

	remoteIP := etwapi.ParseIP(event.EventData[mapping.RemoteIPKey])
	remotePort := etwapi.ParsePort(event.EventData[mapping.RemotePortKey])
	localIP := etwapi.ParseIP(event.EventData[mapping.LocalIPKey])
	localPort := etwapi.ParsePort(event.EventData[mapping.LocalPortKey])

	// Dump full event data for first 10 PID-matched events.
	if matchCount <= 10 {
		e.logger.Info("rawsec: matched PID event detail",
			"event_id", event.System.EventID,
			"state", mapping.State,
			"remote_ip", remoteIP,
			"remote_port", remotePort,
			"local_ip", localIP,
			"local_port", localPort,
			"udp", mapping.IsUDP,
			"all_fields", dumpFieldsRaw(event.EventData))
	}

	if remoteIP == "" || remotePort == 0 {
		e.stats.parseFailures.Add(1)
		e.logger.Info("rawsec: failed to parse remote endpoint",
			"event_id", event.System.EventID,
			"state", mapping.State,
			"remote_ip_key", mapping.RemoteIPKey,
			"remote_port_key", mapping.RemotePortKey,
			"remote_ip_val", fmt.Sprintf("%v (%T)", event.EventData[mapping.RemoteIPKey], event.EventData[mapping.RemoteIPKey]),
			"remote_port_val", fmt.Sprintf("%v (%T)", event.EventData[mapping.RemotePortKey], event.EventData[mapping.RemotePortKey]),
			"all_keys", getKeysRaw(event.EventData))
		return nil
	}

	e.logger.Debug("rawsec: network event",
		"event_id", event.System.EventID,
		"remote", fmt.Sprintf("%s:%d", remoteIP, remotePort),
		"local", fmt.Sprintf("%s:%d", localIP, localPort),
		"udp", mapping.IsUDP,
		"state", mapping.State)

	select {
	case e.events <- etwapi.NetworkEvent{
		PID:        actualPID,
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		LocalIP:    localIP,
		LocalPort:  localPort,
		IsUDP:      mapping.IsUDP,
		State:      mapping.State,
		Timestamp:  event.System.TimeCreated.SystemTime,
		Tool:       toolName,
	}:
	case <-e.ctx.Done():
	}

	return nil
}

// Stop terminates the ETW session and consumer.
func (e *Engine) Stop() {
	e.cancel()
	if e.consumer != nil {
		_ = e.consumer.Stop()
	}
	if e.session != nil {
		_ = e.session.Stop()
	}

	e.logger.Info("rawsec: ETW session stopped",
		"total_events", e.stats.totalEvents.Load(),
		"pid_matches", e.stats.pidMatches.Load(),
		"mapped_events", e.stats.mappedEvents.Load(),
		"parse_failures", e.stats.parseFailures.Load())
}

func getKeysRaw(m map[string]interface{}) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

func dumpFieldsRaw(m map[string]interface{}) []string {
	var fields []string
	for k, v := range m {
		fields = append(fields, fmt.Sprintf("%s=%v(%T)", k, v, v))
	}
	return fields
}
