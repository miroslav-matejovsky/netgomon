//go:build windows

package rawsec

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	rawetw "github.com/0xrawsec/golang-etw/etw"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
)

const toolName = "rawsec"

// Engine implements etw.Engine using the 0xrawsec/golang-etw library.
type Engine struct {
	targetPID   uint32
	session     *rawetw.RealTimeSession
	consumer    *rawetw.Consumer
	events      chan etwapi.NetworkEvent
	ctx         context.Context
	cancel      context.CancelFunc
	logger      *slog.Logger
	totalEvents uint64
}

// New creates a rawsec ETW engine for the given target PID.
func New(targetPID uint32, logger *slog.Logger) *Engine {
	ctx, cancel := context.WithCancel(context.Background())
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
		e.totalEvents++
		var actualPID uint32
		for k, v := range event.EventData {
			if k == "PID" || k == "pid" || k == "ProcessId" || k == "ProcessID" {
				actualPID = etwapi.ParsePID(v)
				break
			}
		}
		if actualPID == 0 {
			actualPID = event.System.Execution.ProcessID
		}

		if actualPID != e.targetPID {
			return nil
		}

		e.logger.Info("rawsec: matched PID event", "event_id", event.System.EventID, "keys", getKeysRaw(event.EventData))

		mapping := etwapi.MapEventID(event.System.EventID)
		if mapping == nil {
			e.logger.Debug("rawsec: unmapped ETW event",
				"event_id", event.System.EventID,
				"pid", event.System.Execution.ProcessID,
				"keys", getKeysRaw(event.EventData))
			return nil
		}

		remoteIP := etwapi.ParseIP(event.EventData[mapping.RemoteIPKey])
		remotePort := etwapi.ParsePort(event.EventData[mapping.RemotePortKey])
		localIP := etwapi.ParseIP(event.EventData[mapping.LocalIPKey])
		localPort := etwapi.ParsePort(event.EventData[mapping.LocalPortKey])

		if remoteIP == "" || remotePort == 0 {
			e.logger.Info("rawsec: failed to parse remote endpoint",
				"event_id", event.System.EventID,
				"remote_ip_key", mapping.RemoteIPKey,
				"remote_port_key", mapping.RemotePortKey,
				"remote_ip_val", fmt.Sprintf("%v", event.EventData[mapping.RemoteIPKey]),
				"remote_port_val", fmt.Sprintf("%v", event.EventData[mapping.RemotePortKey]),
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

	go func() {
		_ = e.consumer.Start()
		close(e.events)
	}()

	e.logger.Info("rawsec: ETW session started", "pid", e.targetPID)
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
	close(e.events)
	e.logger.Info("rawsec: ETW session stopped", "totalEvents", e.totalEvents)
}

func getKeysRaw(m map[string]interface{}) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
