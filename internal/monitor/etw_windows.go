//go:build windows

package monitor

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/0xrawsec/golang-etw/etw"
)

// ETWEngine manages the ETW tracing session.
type ETWEngine struct {
	SessionName string
	TargetPID   uint32
	session     *etw.RealTimeSession
	consumer    *etw.Consumer
	tcpMap      map[string]*TCPEndpointRecord
	udpMap      map[string]*UDPEndpointRecord
	mu          sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	logger      *Logger
}

// NewETWEngine creates a new ETW tracing engine for the target PID.
func NewETWEngine(targetPID uint32, tcpMap map[string]*TCPEndpointRecord, udpMap map[string]*UDPEndpointRecord, logger *Logger) *ETWEngine {
	sessionName := fmt.Sprintf("NetWinMon_%d_%d", targetPID, time.Now().Unix())
	ctx, cancel := context.WithCancel(context.Background())
	return &ETWEngine{
		SessionName: sessionName,
		TargetPID:   targetPID,
		tcpMap:      tcpMap,
		udpMap:      udpMap,
		ctx:         ctx,
		cancel:      cancel,
		logger:      logger,
	}
}

// Start starts the ETW session and consumer.
func (e *ETWEngine) Start() error {
	e.session = etw.NewRealTimeSession(e.SessionName)
	// Stop any pre-existing session with the same name just in case.
	_ = e.session.Stop()

	if err := e.session.Start(); err != nil {
		return fmt.Errorf("failed to start ETW session: %w", err)
	}

	provider, err := etw.ParseProvider("Microsoft-Windows-Kernel-Network")
	if err != nil {
		_ = e.session.Stop()
		return fmt.Errorf("failed to parse provider: %w", err)
	}
	provider.MatchAnyKeyword = 0xFFFFFFFFFFFFFFFF
	provider.EnableLevel = 5 // Verbose

	if err := e.session.EnableProvider(provider); err != nil {
		_ = e.session.Stop()
		return fmt.Errorf("failed to enable provider: %w", err)
	}

	e.consumer = etw.NewRealTimeConsumer(e.ctx)
	e.consumer.FromSessions(e.session)

	e.consumer.EventCallback = func(event *etw.Event) error {
		if event.System.Execution.ProcessID != e.TargetPID {
			return nil
		}

		remoteIP, remotePort, localIP, localPort, isUDP, state := parseEventNetworkTuple(event)

		e.logger.Log("ETW Event: EventID=%d ProcessID=%d Remote=%s:%d Local=%s:%d IsUDP=%t State=%s",
			event.System.EventID, event.System.Execution.ProcessID, remoteIP, remotePort, localIP, localPort, isUDP, state)

		if remoteIP == "" || remotePort == 0 {
			return nil
		}

		nowStr := event.System.TimeCreated.SystemTime.UTC().Format(time.RFC3339)

		e.mu.Lock()
		defer e.mu.Unlock()

		if isUDP {
			key := fmt.Sprintf("%s:%d", remoteIP, remotePort)
			if rec, ok := e.udpMap[key]; ok {
				rec.LastSeen = nowStr
				rec.Count++
			} else {
				e.udpMap[key] = &UDPEndpointRecord{
					RemoteAddress: remoteIP,
					RemotePort:    remotePort,
					FirstSeen:     nowStr,
					LastSeen:      nowStr,
					Count:         1,
					InferredHTTP:  inferHTTP(0, remotePort),
				}
			}
		} else {
			key := fmt.Sprintf("%s:%d", remoteIP, remotePort)
			if rec, ok := e.tcpMap[key]; ok {
				rec.LastSeen = nowStr
				rec.Count++
				rec.States[state]++
			} else {
				e.tcpMap[key] = &TCPEndpointRecord{
					RemoteAddress: remoteIP,
					RemotePort:    remotePort,
					FirstSeen:     nowStr,
					LastSeen:      nowStr,
					Count:         1,
					InferredHTTP:  inferHTTP(0, remotePort),
					States:        map[string]int{state: 1},
				}
			}
		}
		return nil
	}

	go func() {
		_ = e.consumer.Start()
	}()

	return nil
}

// Stop stops the ETW session and consumer.
func (e *ETWEngine) Stop() {
	e.cancel()
	if e.consumer != nil {
		_ = e.consumer.Stop()
	}
	if e.session != nil {
		_ = e.session.Stop()
	}
}

func parseEventNetworkTuple(e *etw.Event) (remoteIP string, remotePort uint16, localIP string, localPort uint16, isUDP bool, state string) {
	id := e.System.EventID
	switch id {
	case 10, 20: // TCP Recv
		remoteIP = parseIP(e.EventData["saddr"])
		remotePort = parsePort(e.EventData["sport"])
		localIP = parseIP(e.EventData["daddr"])
		localPort = parsePort(e.EventData["dport"])
		state = "RECEIVE"
	case 11, 21: // TCP Send
		remoteIP = parseIP(e.EventData["daddr"])
		remotePort = parsePort(e.EventData["dport"])
		localIP = parseIP(e.EventData["saddr"])
		localPort = parsePort(e.EventData["sport"])
		state = "SEND"
	case 12, 16: // TCP Connect
		remoteIP = parseIP(e.EventData["daddr"])
		remotePort = parsePort(e.EventData["dport"])
		localIP = parseIP(e.EventData["saddr"])
		localPort = parsePort(e.EventData["sport"])
		state = "CONNECT"
	case 13, 22: // TCP Disconnect
		remoteIP = parseIP(e.EventData["daddr"])
		remotePort = parsePort(e.EventData["dport"])
		localIP = parseIP(e.EventData["saddr"])
		localPort = parsePort(e.EventData["sport"])
		state = "DISCONNECT"
	case 14, 23: // TCP Reconnect
		remoteIP = parseIP(e.EventData["daddr"])
		remotePort = parsePort(e.EventData["dport"])
		localIP = parseIP(e.EventData["saddr"])
		localPort = parsePort(e.EventData["sport"])
		state = "RECONNECT"
	case 15, 18: // TCP Accept
		remoteIP = parseIP(e.EventData["saddr"])
		remotePort = parsePort(e.EventData["sport"])
		localIP = parseIP(e.EventData["daddr"])
		localPort = parsePort(e.EventData["dport"])
		state = "ACCEPT"
	case 17: // TCP Connect Fail
		remoteIP = parseIP(e.EventData["daddr"])
		remotePort = parsePort(e.EventData["dport"])
		localIP = parseIP(e.EventData["saddr"])
		localPort = parsePort(e.EventData["sport"])
		state = "CONNECT_FAIL"
	case 26, 28, 43: // UDP Recv
		remoteIP = parseIP(e.EventData["saddr"])
		remotePort = parsePort(e.EventData["sport"])
		localIP = parseIP(e.EventData["daddr"])
		localPort = parsePort(e.EventData["dport"])
		isUDP = true
		state = "RECEIVE"
	case 27, 29, 42: // UDP Send
		remoteIP = parseIP(e.EventData["daddr"])
		remotePort = parsePort(e.EventData["dport"])
		localIP = parseIP(e.EventData["saddr"])
		localPort = parsePort(e.EventData["sport"])
		isUDP = true
		state = "SEND"
	}
	return
}

func parseIP(val interface{}) string {
	if val == nil {
		return ""
	}
	switch v := val.(type) {
	case string:
		return v
	case net.IP:
		return v.String()
	case []byte:
		if len(v) == 4 || len(v) == 16 {
			return net.IP(v).String()
		}
	case uint32:
		ip := net.IPv4(byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
		return ip.String()
	}
	return fmt.Sprintf("%v", val)
}

func parsePort(val interface{}) uint16 {
	if val == nil {
		return 0
	}
	switch v := val.(type) {
	case uint16:
		return v
	case int:
		return uint16(v)
	case uint32:
		return uint16(v)
	case float64:
		return uint16(v)
	}
	var p uint16
	_, _ = fmt.Sscanf(fmt.Sprintf("%v", val), "%d", &p)
	return p
}
