//go:build windows

package custom

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	etwapi "github.com/miroslav-matejovsky/netwinmon/internal/etw"
)

const toolName = "custom"

// engineStats tracks diagnostic counters.
type engineStats struct {
	totalEvents   atomic.Uint64
	mappedEvents  atomic.Uint64
	pidMatches    atomic.Uint64
	parseFailures atomic.Uint64
	eventIDCounts sync.Map // map[uint16]*atomic.Uint64
}

func (s *engineStats) incEventID(id uint16) {
	val, _ := s.eventIDCounts.LoadOrStore(id, new(atomic.Uint64))
	val.(*atomic.Uint64).Add(1)
}

// Engine implements etw.Engine using direct Win32 ETW syscalls.
type Engine struct {
	targetPID     uint32
	sessionName   string
	sessionHandle uintptr
	traceHandle   uintptr
	events        chan etwapi.NetworkEvent
	ctx           context.Context
	cancel        context.CancelFunc
	logger        *slog.Logger
	stats         engineStats
	stopped       chan struct{}
}

// New creates a custom ETW engine for the given target PID.
func New(ctx context.Context, targetPID uint32, logger *slog.Logger) *Engine {
	ctx, cancel := context.WithCancel(ctx)
	sessionName := fmt.Sprintf("NetWinMon_custom_%d_%d", targetPID, time.Now().Unix())
	return &Engine{
		targetPID:   targetPID,
		sessionName: sessionName,
		events:      make(chan etwapi.NetworkEvent, 256),
		ctx:         ctx,
		cancel:      cancel,
		logger:      logger,
		stopped:     make(chan struct{}),
	}
}

// Events returns the channel of captured network events.
func (e *Engine) Events() <-chan etwapi.NetworkEvent {
	return e.events
}

// Start initializes the ETW session and begins consuming events.
func (e *Engine) Start() error {
	e.logger.Info("custom: starting ETW engine", "pid", e.targetPID, "session", e.sessionName)

	// Clean up any orphaned session with same name.
	stopSession(e.sessionName)

	sessionNamePtr, err := windows.UTF16PtrFromString(e.sessionName)
	if err != nil {
		return fmt.Errorf("custom: invalid session name: %w", err)
	}

	// Allocate properties buffer. Session name is stored after the struct.
	var buf [eventTracePropertiesBufferSize]byte
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(len(buf))
	props.Wnode.Flags = wnodeFlagTracedGUID
	props.Wnode.ClientContext = eventTraceClockQPC
	props.LogFileMode = eventTraceRealTimeMode
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))
	props.BufferSize = 64 // 64 KB buffers
	props.MinimumBuffers = 4
	props.MaximumBuffers = 64

	// Start trace session.
	sessionHandle, err := startTrace(sessionNamePtr, props)
	if err != nil {
		return fmt.Errorf("custom: %w", err)
	}
	e.sessionHandle = sessionHandle
	e.logger.Info("custom: trace session started", "handle", sessionHandle)

	// Enable Microsoft-Windows-Kernel-Network provider.
	providerGUID := kernelNetworkProviderGUID
	err = enableTraceEx2(
		sessionHandle,
		&providerGUID,
		eventControlCodeEnableProvider,
		traceLevelVerbose,
		0xFFFFFFFFFFFFFFFF, // match any keyword
		0,                  // match all keyword
	)
	if err != nil {
		e.stopSession()
		return fmt.Errorf("custom: %w", err)
	}
	e.logger.Info("custom: provider enabled", "provider", "Microsoft-Windows-Kernel-Network")

	// Set up the event record callback. We store a pointer to the engine
	// in a global so the callback can find it.
	registerEngine(e)

	// Open trace for consuming.
	var logfile eventTraceLogfileW
	logfileSessionName, _ := windows.UTF16PtrFromString(e.sessionName)
	logfile.LoggerName = logfileSessionName
	logfile.Union1 = processTraceModeRealTime | processTraceModeEventRecord
	logfile.EventRecordCallback = windows.NewCallback(eventRecordCallbackTrampoline)
	logfile.Context = unsafe.Pointer(e)

	traceHandle, err := openTrace(&logfile)
	if err != nil {
		e.stopSession()
		unregisterEngine(e)
		return fmt.Errorf("custom: %w", err)
	}
	e.traceHandle = traceHandle
	e.logger.Info("custom: trace opened", "trace_handle", traceHandle)

	// ProcessTrace goroutine - must lock OS thread.
	go func() {
		defer close(e.events)
		defer func() { close(e.stopped) }()

		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		e.logger.Info("custom: starting ProcessTrace (locked OS thread)")
		err := processTrace(traceHandle)
		if err != nil {
			// Error 1223 (ERROR_CANCELLED) is expected when CloseTrace is called.
			e.logger.Info("custom: ProcessTrace returned", "error", err)
		} else {
			e.logger.Info("custom: ProcessTrace completed cleanly")
		}
	}()

	// Context cancellation goroutine - calls CloseTrace to unblock ProcessTrace.
	go func() {
		<-e.ctx.Done()
		e.logger.Info("custom: context cancelled, closing trace")
		if err := closeTrace(e.traceHandle); err != nil {
			e.logger.Warn("custom: CloseTrace error", "error", err)
		}
	}()

	e.logger.Info("custom: ETW engine started", "pid", e.targetPID)
	return nil
}

// Stop terminates the ETW session.
func (e *Engine) Stop() {
	e.cancel()

	// Wait for ProcessTrace goroutine to finish.
	<-e.stopped

	e.stopSession()
	unregisterEngine(e)

	e.logger.Info("custom: ETW engine stopped",
		"total_events", e.stats.totalEvents.Load(),
		"pid_matches", e.stats.pidMatches.Load(),
		"mapped_events", e.stats.mappedEvents.Load(),
		"parse_failures", e.stats.parseFailures.Load())
}

func (e *Engine) stopSession() {
	stopSession(e.sessionName)
}

// processEventRecord handles a single EVENT_RECORD from the callback.
func (e *Engine) processEventRecord(rec *eventRecord) {
	total := e.stats.totalEvents.Add(1)
	eventID := rec.EventHeader.EventDescriptor.Id
	e.stats.incEventID(eventID)

	// Parse raw event data.
	parsed := parseEventData(eventID, rec.UserData, rec.UserDataLength)
	if parsed == nil {
		if total <= 20 {
			e.logger.Debug("custom: unparseable event",
				"event_id", eventID,
				"user_data_len", rec.UserDataLength,
				"exec_pid", rec.EventHeader.ProcessId)
		}
		return
	}

	// Log first 20 events for diagnostics.
	if total <= 20 {
		e.logger.Info("custom: event sample",
			"event_id", eventID,
			"data_pid", parsed.PID,
			"exec_pid", rec.EventHeader.ProcessId,
			"src", fmt.Sprintf("%s:%d", parsed.SrcAddr, parsed.SrcPort),
			"dst", fmt.Sprintf("%s:%d", parsed.DstAddr, parsed.DstPort))
	}

	// Check PID match.
	actualPID := parsed.PID
	if actualPID == 0 {
		actualPID = rec.EventHeader.ProcessId
	}

	if actualPID != e.targetPID {
		return
	}

	e.stats.pidMatches.Add(1)
	matchCount := e.stats.pidMatches.Load()

	mapping := etwapi.MapEventID(eventID)
	if mapping == nil {
		e.logger.Debug("custom: unmapped event for target PID",
			"event_id", eventID,
			"pid", actualPID)
		return
	}

	e.stats.mappedEvents.Add(1)

	// Extract fields based on mapping direction.
	var remoteIP, localIP string
	var remotePort, localPort uint16

	// MapEventID returns keys like "daddr"/"saddr" to indicate which address is remote.
	// For custom engine, we already have parsed addresses; map them accordingly.
	if mapping.RemoteIPKey == "daddr" {
		remoteIP = parsed.DstAddr.String()
		remotePort = parsed.DstPort
		localIP = parsed.SrcAddr.String()
		localPort = parsed.SrcPort
	} else {
		remoteIP = parsed.SrcAddr.String()
		remotePort = parsed.SrcPort
		localIP = parsed.DstAddr.String()
		localPort = parsed.DstPort
	}

	if matchCount <= 10 {
		e.logger.Info("custom: matched PID event",
			"event_id", eventID,
			"state", mapping.State,
			"remote", fmt.Sprintf("%s:%d", remoteIP, remotePort),
			"local", fmt.Sprintf("%s:%d", localIP, localPort),
			"udp", mapping.IsUDP)
	}

	if remoteIP == "" || remotePort == 0 {
		e.stats.parseFailures.Add(1)
		e.logger.Info("custom: failed to parse remote endpoint",
			"event_id", eventID,
			"state", mapping.State)
		return
	}

	ts := time.Now()
	if rec.EventHeader.TimeStamp != 0 {
		// Convert QPC timestamp - use current time as approximation.
		// Exact QPC-to-wallclock conversion requires frequency; current time is close enough.
		ts = time.Now()
	}

	select {
	case e.events <- etwapi.NetworkEvent{
		PID:        actualPID,
		RemoteIP:   remoteIP,
		RemotePort: remotePort,
		LocalIP:    localIP,
		LocalPort:  localPort,
		IsUDP:      mapping.IsUDP,
		State:      mapping.State,
		Timestamp:  ts,
		Tool:       toolName,
	}:
	case <-e.ctx.Done():
	}
}

// Global engine registry for callback routing.
// The EVENT_TRACE_LOGFILEW.Context field carries the engine pointer,
// but we also keep a registry as defense-in-depth.
var (
	engineRegistryMu sync.RWMutex
	engineRegistry   = make(map[uintptr]*Engine)
)

func registerEngine(e *Engine) {
	engineRegistryMu.Lock()
	engineRegistry[uintptr(unsafe.Pointer(e))] = e
	engineRegistryMu.Unlock()
}

func unregisterEngine(e *Engine) {
	engineRegistryMu.Lock()
	delete(engineRegistry, uintptr(unsafe.Pointer(e)))
	engineRegistryMu.Unlock()
}

// eventRecordCallbackTrampoline is the Win32 callback invoked by ProcessTrace.
// It receives a pointer to EVENT_RECORD. The UserContext field points to our Engine.
// Parameter is unsafe.Pointer to avoid go vet "possible misuse of unsafe.Pointer" warning;
// Win32 passes a native pointer, not a Go-managed address.
func eventRecordCallbackTrampoline(recordPtr unsafe.Pointer) uintptr {
	if recordPtr == nil {
		return 0
	}
	rec := (*eventRecord)(recordPtr)

	// Get engine from UserContext (set via EVENT_TRACE_LOGFILEW.Context).
	eng := (*Engine)(rec.UserContext)
	if eng == nil {
		return 0
	}

	eng.processEventRecord(rec)
	return 0
}
