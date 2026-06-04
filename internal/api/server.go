package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/miroslav-matejovsky/netwinmon/internal/monitor"
)

// Server represents the HTTP API server.
type Server struct {
	addr    string
	monitor *monitor.Monitor
	srv     *http.Server
	mu      sync.Mutex
}

// NewServer creates a new API server.
func NewServer(addr string, mon *monitor.Monitor) *Server {
	return &Server{
		addr:    addr,
		monitor: mon,
	}
}

// Start starts the HTTP server in a goroutine.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	mux := http.NewServeMux()
	mux.HandleFunc("/state", s.handleState)
	mux.HandleFunc("/state/", s.handleStatePID)

	s.srv = &http.Server{
		Addr:    s.addr,
		Handler: mux,
	}

	go func() {
		if err := s.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Printf("API Server error: %v\n", err)
		}
	}()

	return nil
}

// Stop stops the HTTP server.
func (s *Server) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.srv != nil {
		return s.srv.Shutdown(ctx)
	}
	return nil
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	state := s.monitor.GetState()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(state); err != nil {
		http.Error(w, "Failed to encode state", http.StatusInternalServerError)
	}
}

func (s *Server) handleStatePID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	pidStr := strings.TrimPrefix(r.URL.Path, "/state/")
	pid, err := strconv.ParseUint(pidStr, 10, 32)
	if err != nil {
		http.Error(w, "Invalid PID", http.StatusBadRequest)
		return
	}

	state := s.monitor.GetProcessState(uint32(pid))
	if state == nil {
		http.Error(w, "Process not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(state); err != nil {
		http.Error(w, "Failed to encode state", http.StatusInternalServerError)
	}
}
