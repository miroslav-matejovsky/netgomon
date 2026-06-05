//go:build windows

package custom

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modAdvapi32        = windows.NewLazySystemDLL("advapi32.dll")
	procStartTraceW    = modAdvapi32.NewProc("StartTraceW")
	procEnableTraceEx2 = modAdvapi32.NewProc("EnableTraceEx2")
	procControlTraceW  = modAdvapi32.NewProc("ControlTraceW")
	procOpenTraceW     = modAdvapi32.NewProc("OpenTraceW")
	procProcessTrace   = modAdvapi32.NewProc("ProcessTrace")
	procCloseTrace     = modAdvapi32.NewProc("CloseTrace")
)

// startTrace wraps StartTraceW. Returns session handle on success.
func startTrace(sessionName *uint16, props *eventTraceProperties) (uintptr, error) {
	var sessionHandle uintptr
	r1, _, _ := procStartTraceW.Call(
		uintptr(unsafe.Pointer(&sessionHandle)),
		uintptr(unsafe.Pointer(sessionName)),
		uintptr(unsafe.Pointer(props)),
	)
	if r1 != errorSuccess {
		return 0, fmt.Errorf("StartTraceW failed: error %d", r1)
	}
	return sessionHandle, nil
}

// enableTraceEx2 enables a provider on the session.
func enableTraceEx2(
	sessionHandle uintptr,
	providerGUID *windows.GUID,
	controlCode uint32,
	level uint8,
	matchAnyKeyword uint64,
	matchAllKeyword uint64,
) error {
	r1, _, _ := procEnableTraceEx2.Call(
		sessionHandle,
		uintptr(unsafe.Pointer(providerGUID)),
		uintptr(controlCode),
		uintptr(level),
		uintptr(matchAnyKeyword),
		uintptr(matchAllKeyword),
		0, // timeout
		0, // enable parameters (nil)
	)
	if r1 != errorSuccess {
		return fmt.Errorf("EnableTraceEx2 failed: error %d", r1)
	}
	return nil
}

// controlTrace wraps ControlTraceW (stop or query session).
func controlTrace(sessionHandle uintptr, sessionName *uint16, props *eventTraceProperties, controlCode uint32) error {
	r1, _, _ := procControlTraceW.Call(
		sessionHandle,
		uintptr(unsafe.Pointer(sessionName)),
		uintptr(unsafe.Pointer(props)),
		uintptr(controlCode),
	)
	if r1 != errorSuccess {
		return fmt.Errorf("ControlTraceW failed: error %d", r1)
	}
	return nil
}

// openTrace wraps OpenTraceW. Returns a trace handle for ProcessTrace.
func openTrace(logfile *eventTraceLogfileW) (uintptr, error) {
	r1, _, err := procOpenTraceW.Call(uintptr(unsafe.Pointer(logfile)))
	if r1 == invalidProcessTraceHandle {
		return 0, fmt.Errorf("OpenTraceW failed: %w", err)
	}
	return r1, nil
}

// processTrace wraps ProcessTrace. Blocks until trace is closed or error.
func processTrace(traceHandle uintptr) error {
	r1, _, _ := procProcessTrace.Call(
		uintptr(unsafe.Pointer(&traceHandle)),
		1, // handle count
		0, // start time (nil = from beginning)
		0, // end time (nil = no end)
	)
	if r1 != errorSuccess {
		return fmt.Errorf("ProcessTrace returned: error %d", r1)
	}
	return nil
}

// closeTrace wraps CloseTrace. Unblocks ProcessTrace.
func closeTrace(traceHandle uintptr) error {
	r1, _, _ := procCloseTrace.Call(traceHandle)
	if r1 != errorSuccess {
		return fmt.Errorf("CloseTrace failed: error %d", r1)
	}
	return nil
}

// stopSession stops an ETW session by name. Ignores errors (used for cleanup).
func stopSession(sessionName string) {
	namePtr, err := windows.UTF16PtrFromString(sessionName)
	if err != nil {
		return
	}

	var buf [eventTracePropertiesBufferSize]byte
	props := (*eventTraceProperties)(unsafe.Pointer(&buf[0]))
	props.Wnode.BufferSize = uint32(len(buf))
	props.LoggerNameOffset = uint32(unsafe.Sizeof(eventTraceProperties{}))

	_ = controlTrace(0, namePtr, props, eventTraceControlStop)
}
