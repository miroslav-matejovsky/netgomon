//go:build windows

package goetw

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	teketw "github.com/tekert/goetw/etw"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
)

const toolName = "goetw"

// Engine implements etw.Engine using the tekert/goetw library.
type Engine struct {
	targetPID uint32
	session   *teketw.RealTimeSession
	consumer  *teketw.Consumer
	events    chan etwapi.NetworkEvent
	ctx       context.Context
	cancel    context.CancelFunc
	logger    *slog.Logger
}

// New creates a goetw ETW engine for the given target PID.
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
			if event.System.Execution.ProcessID != e.targetPID {
				return
			}

			mapping := etwapi.MapEventID(event.System.EventID)
			if mapping == nil {
				e.logger.Debug("goetw: unmapped ETW event",
					"event_id", event.System.EventID,
					"pid", event.System.Execution.ProcessID)
				return
			}

			remoteIPData, _ := event.GetProperty(mapping.RemoteIPKey)
			remoteIP := etwapi.ParseIP(remoteIPData)

			remotePortData, _ := event.GetProperty(mapping.RemotePortKey)
			remotePort := etwapi.ParsePort(remotePortData)

			localIPData, _ := event.GetProperty(mapping.LocalIPKey)
			localIP := etwapi.ParseIP(localIPData)

			localPortData, _ := event.GetProperty(mapping.LocalPortKey)
			localPort := etwapi.ParsePort(localPortData)

			if remoteIP == "" || remotePort == 0 {
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
		}); err != nil {
			e.logger.Error("goetw: event processing error", "error", err)
		}
	}()

	if err := e.consumer.Start(); err != nil {
		_ = e.session.Stop()
		return fmt.Errorf("goetw: failed to start consumer: %w", err)
	}

	e.logger.Info("goetw: ETW session started", "pid", e.targetPID)
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
	e.logger.Info("goetw: ETW session stopped")
}
