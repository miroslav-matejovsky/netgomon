package goetw

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/miroslav-matejovsky/netwinmon/internal/privilege"
	teketw "github.com/tekert/goetw/etw"
)

func TestETWEvents(t *testing.T) {
	if !privilege.IsElevated() {
		t.Skip("requires admin privileges for ETW session")
	}

	session := teketw.NewRealTimeSession("Test_NetWinMon_Session")
	_ = session.Stop() // cleanup

	err := session.Start()
	if err != nil {
		t.Skipf("Skipping test: cannot start ETW session: %v", err)
	}
	defer func() { _ = session.Stop() }()

	provider, err := teketw.ParseProvider("Microsoft-Windows-Kernel-Network")
	if err != nil {
		t.Fatalf("ParseProvider failed: %v", err)
	}
	provider.MatchAnyKeyword = 0xFFFFFFFFFFFFFFFF
	provider.EnableLevel = 5

	err = session.EnableProvider(provider)
	if err != nil {
		t.Fatalf("EnableProvider failed: %v", err)
	}

	consumer := teketw.NewConsumer(context.Background())
	consumer.FromSessions(session)

	eventCh := make(chan string, 100)

	go func() {
		_ = consumer.ProcessEvents(func(event *teketw.Event) {
			if event.System.EventID == 10 || event.System.EventID == 12 || event.System.EventID == 11 {
				keys := getKeysGoetw(event.EventData)
				pid := event.System.Execution.ProcessID
				// Try to find the real PID
				pidFromData := uint32(0)
				for _, p := range event.EventData {
					if p.Name == "PID" || p.Name == "ProcessId" || p.Name == "processId" {
						pidFromData = p.Value.(uint32)
					}
				}
				eventCh <- fmt.Sprintf("Event %d: PID=%d DataPID=%d Keys=%v", event.System.EventID, pid, pidFromData, keys)
			}
		})
	}()

	err = consumer.Start()
	if err != nil {
		t.Fatalf("consumer Start failed: %v", err)
	}
	defer func() { _ = consumer.Stop() }()

	// Make a connection
	go func() {
		time.Sleep(500 * time.Millisecond)
		_, _ = http.Get("http://example.com")
	}()

	select {
	case evt := <-eventCh:
		t.Logf("Got event: %s", evt)
	case <-time.After(2 * time.Second):
		t.Logf("No events captured")
	}
}
