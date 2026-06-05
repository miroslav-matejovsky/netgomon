//go:build windows

package custom

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Microsoft-Windows-Kernel-Network provider GUID.
var kernelNetworkProviderGUID = windows.GUID{
	Data1: 0x7DD42A49,
	Data2: 0x5329,
	Data3: 0x4832,
	Data4: [8]byte{0x8D, 0xFD, 0x43, 0xD9, 0x79, 0x15, 0x3A, 0x88},
}

// ETW constants.
const (
	// Session control codes for ControlTraceW.
	eventTraceControlStop  = 1
	eventTraceControlQuery = 0

	// Enable provider control codes for EnableTraceEx2.
	eventControlCodeEnableProvider  = 1
	eventControlCodeDisableProvider = 0

	// Trace level.
	traceLevelVerbose = 5

	// Log file mode flags.
	eventTraceRealTimeMode = 0x00000100

	// WNODE flags.
	wnodeFlagTracedGUID = 0x00020000

	// ProcessTrace mode flags (set in EVENT_TRACE_LOGFILEW.ProcessTraceMode).
	processTraceModeRealTime    = 0x00000100
	processTraceModeEventRecord = 0x10000000

	// Clock types.
	eventTraceClockQPC = 1 // QueryPerformanceCounter

	// Invalid trace handle.
	invalidProcessTraceHandle = ^uintptr(0) // 0xFFFFFFFFFFFFFFFF on 64-bit

	// Error codes.
	errorAlreadyExists = 183
	errorSuccess       = 0
)

// WNODE_HEADER is the header of an event tracing node.
// Must match Windows layout exactly.
type wnodeHeader struct {
	BufferSize    uint32
	ProviderId    uint32
	HistoricalCtx uint64 // union: HistoricalContext / {Version, Linkage}
	TimeStamp     int64  // LARGE_INTEGER (union with KernelHandle)
	Guid          windows.GUID
	ClientContext uint32
	Flags         uint32
}

// EVENT_TRACE_PROPERTIES is used with StartTraceW and ControlTraceW.
// This is a variable-length structure; the session name follows at LoggerNameOffset.
type eventTraceProperties struct {
	Wnode               wnodeHeader
	BufferSize          uint32 // in KB
	MinimumBuffers      uint32
	MaximumBuffers      uint32
	MaximumFileSize     uint32
	LogFileMode         uint32
	FlushTimer          uint32
	EnableFlags         uint32
	AgeLimit            int32 // union with FlushThreshold
	NumberOfBuffers     uint32
	FreeBuffers         uint32
	EventsLost          uint32
	BuffersWritten      uint32
	LogBuffersLost      uint32
	RealTimeBuffersLost uint32
	LoggerThreadId      uintptr // HANDLE
	LogFileNameOffset   uint32
	LoggerNameOffset    uint32
}

// eventTracePropertiesBuffer is a fixed-size buffer that holds eventTraceProperties
// followed by the session name string. 1024 bytes is generous for session names.
const eventTracePropertiesBufferSize = 1024

// EVENT_HEADER is the header inside EVENT_RECORD.
type eventHeader struct {
	Size            uint16
	HeaderType      uint16
	Flags           uint16
	EventProperty   uint16
	ThreadId        uint32
	ProcessId       uint32
	TimeStamp       int64 // LARGE_INTEGER
	ProviderId      windows.GUID
	EventDescriptor eventDescriptor
	Time            uint64 // union: ProcessorTime or {KernelTime, UserTime}
	ActivityId      windows.GUID
}

// EVENT_DESCRIPTOR identifies the event.
type eventDescriptor struct {
	Id      uint16
	Version uint8
	Channel uint8
	Level   uint8
	Opcode  uint8
	Task    uint16
	Keyword uint64
}

// ETW_BUFFER_CONTEXT provides context about the buffer.
type etwBufferContext struct {
	Union    uint16 // union of ProcessorNumber/ProcessorIndex + LoggerId
	LoggerId uint16
}

// EVENT_RECORD is what ProcessTrace delivers to the callback.
type eventRecord struct {
	EventHeader       eventHeader
	BufferContext     etwBufferContext
	ExtendedDataCount uint16
	UserDataLength    uint16
	ExtendedData      unsafe.Pointer // PEVENT_HEADER_EXTENDED_DATA_ITEM
	UserData          unsafe.Pointer // pointer to raw event payload
	UserContext       unsafe.Pointer // context set by consumer
}

// EVENT_TRACE_LOGFILEW is used with OpenTraceW. Fields that are unions are
// represented by the relevant member for real-time mode.
type eventTraceLogfileW struct {
	LogFileName   *uint16 // not used for real-time
	LoggerName    *uint16 // session name
	CurrentTime   int64
	BuffersRead   uint32
	Union1        uint32 // LogFileMode (real-time) or ProcessTraceMode
	CurrentEvent  eventTrace
	LogfileHeader traceLogfileHeader
	// Callback pointers - unions.
	// For EVENT_RECORD mode, we use EventRecordCallback.
	BufferCallback      uintptr
	BufferSize          uint32
	Filled              uint32
	EventsLost          uint32
	EventRecordCallback uintptr // union with EventCallback; used when PROCESS_TRACE_MODE_EVENT_RECORD set
	IsKernelTrace       uint32
	Context             unsafe.Pointer
}

// eventTrace is the legacy EVENT_TRACE structure (inside EVENT_TRACE_LOGFILEW).
// We don't use it directly but need it for correct struct layout.
type eventTrace struct {
	Header           [80]byte // EVENT_TRACE_HEADER (80 bytes on 64-bit)
	InstanceId       uint32
	ParentInstanceId uint32
	ParentGuid       windows.GUID
	MofData          unsafe.Pointer
	MofLength        uint32
	UnionCtx         uint32
}

// traceLogfileHeader is inside EVENT_TRACE_LOGFILEW.
// We need it for layout but don't read it. Padded to known size.
type traceLogfileHeader struct {
	BufferSize         uint32
	VersionUnion       uint32
	ProviderVersion    uint32
	NumberOfProcessors uint32
	EndTime            int64
	TimerResolution    uint32
	MaximumFileSize    uint32
	LogFileMode        uint32
	BuffersWritten     uint32
	GuidUnion          [16]byte
	LoggerName         uintptr
	LogFileName        uintptr
	TimeZone           [176]byte // TIME_ZONE_INFORMATION
	BootTime           int64
	PerfFreq           int64
	StartTime          int64
	ReservedFlags      uint32
	BuffersLost        uint32
}
