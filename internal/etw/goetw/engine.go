//go:build windows

package goetw

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	teketw "github.com/tekert/goetw/etw"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
)

const toolName = "goetw"

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

// Engine implements etw.Engine using the tekert/goetw library.
type Engine struct {
	targetPID uint32
	session   *teketw.RealTimeSession
	consumer  *teketw.Consumer
	events    chan etwapi.NetworkEvent
	ctx       context.Context
	cancel    context.CancelFunc
	logger    *slog.Logger
	stats     engineStats
}

// New creates a goetw ETW engine for the given target PID.
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
	sessionName := fmt.Sprintf("NetWinMon_goetw_%d_%d", e.targetPID, time.Now().Unix())
	e.session = teketw.NewRealTimeSession(sessionName)

	// stop any pre-existing session with same name
	_ = e.session.Stop()

	if err := e.session.Start(); err != nil {
		return fmt.Errorf("goetw: failed to start ETW session: %w", err)
	}

	provider, err := teketw.ParseProvider("Microsoft-Windows-Kernel-Network")
	if err != nil {
		_ = e.session.Stop()
		return fmt.Errorf("goetw: failed to parse provider: %w", err)
	}
	provider.MatchAnyKeyword = 0xFFFFFFFFFFFFFFFF
	provider.EnableLevel = 5

	if err := e.session.EnableProvider(provider); err != nil {
		_ = e.session.Stop()
		return fmt.Errorf("goetw: failed to enable provider: %w", err)
	}

	e.consumer = teketw.NewConsumer(e.ctx)
	e.consumer.FromSessions(e.session)

	// ProcessEvents runs the callback for each event and blocks.
	go func() {
		if err := e.consumer.ProcessEvents(func(event *teketw.Event) {
			e.processEvent(event)
		}); err != nil {
			e.logger.Error("goetw: event processing error", "error", err)
		}
		close(e.events)
	}()

	if err := e.consumer.Start(); err != nil {
		_ = e.session.Stop()
		return fmt.Errorf("goetw: failed to start consumer: %w", err)
	}

	e.logger.Info("goetw: ETW session started", "pid", e.targetPID)
	return nil
}

func (e *Engine) processEvent(event *teketw.Event) {
	total := e.stats.totalEvents.Add(1)
	e.stats.incEventID(event.System.EventID)

	// Extract PID using case-insensitive matching.
	pairs := make([]etwapi.NamedValue, len(event.EventData))
	for i, p := range event.EventData {
		pairs[i] = etwapi.NamedValue{Name: p.Name, Value: p.Value}
	}
	actualPID := etwapi.FindPIDInSlice(pairs)
	pidSource := "eventdata"
	if actualPID == 0 {
		actualPID = event.System.Execution.ProcessID
		pidSource = "execution"
	}

	// Log first 20 events for diagnostics.
	if total <= 20 {
		e.logger.Info("goetw: event sample",
			"event_id", event.System.EventID,
			"exec_pid", event.System.Execution.ProcessID,
			"data_pid", actualPID,
			"pid_source", pidSource,
			"keys", getKeysGoetw(event.EventData))
	}

	if actualPID != e.targetPID {
		return
	}

	e.stats.pidMatches.Add(1)
	matchCount := e.stats.pidMatches.Load()

	mapping := etwapi.MapEventID(event.System.EventID)
	if mapping == nil {
		e.logger.Debug("goetw: unmapped event for target PID",
			"event_id", event.System.EventID,
			"pid", actualPID)
		return
	}

	e.stats.mappedEvents.Add(1)

	remoteIPData, _ := event.GetProperty(mapping.RemoteIPKey)
	remoteIP := etwapi.ParseIP(remoteIPData)

	remotePortData, _ := event.GetProperty(mapping.RemotePortKey)
	remotePort := etwapi.ParsePort(remotePortData)

	localIPData, _ := event.GetProperty(mapping.LocalIPKey)
	localIP := etwapi.ParseIP(localIPData)

	localPortData, _ := event.GetProperty(mapping.LocalPortKey)
	localPort := etwapi.ParsePort(localPortData)

	// Dump full event data for first 10 PID-matched events.
	if matchCount <= 10 {
		e.logger.Info("goetw: matched PID event detail",
			"event_id", event.System.EventID,
			"state", mapping.State,
			"remote_ip", remoteIP,
			"remote_port", remotePort,
			"local_ip", localIP,
			"local_port", localPort,
			"udp", mapping.IsUDP,
			"all_fields", dumpFieldsGoetw(event.EventData))
	}

	if remoteIP == "" || remotePort == 0 {
		e.stats.parseFailures.Add(1)
		e.logger.Info("goetw: failed to parse remote endpoint",
			"event_id", event.System.EventID,
			"state", mapping.State,
			"remote_ip_key", mapping.RemoteIPKey,
			"remote_port_key", mapping.RemotePortKey,
			"remote_ip_raw", fmt.Sprintf("%v (%T)", remoteIPData, remoteIPData),
			"remote_port_raw", fmt.Sprintf("%v (%T)", remotePortData, remotePortData),
			"all_keys", getKeysGoetw(event.EventData))
		return
	}

	e.logger.Debug("goetw: network event",
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

	e.logger.Info("goetw: ETW session stopped",
		"total_events", e.stats.totalEvents.Load(),
		"pid_matches", e.stats.pidMatches.Load(),
		"mapped_events", e.stats.mappedEvents.Load(),
		"parse_failures", e.stats.parseFailures.Load())
}

func getKeysGoetw(props teketw.Properties) []string {
	var keys []string
	for _, p := range props {
		keys = append(keys, p.Name)
	}
	return keys
}

func dumpFieldsGoetw(props teketw.Properties) []string {
	var fields []string
	for _, p := range props {
		fields = append(fields, fmt.Sprintf("%s=%v(%T)", p.Name, p.Value, p.Value))
	}
	return fields
}
