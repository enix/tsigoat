// Package admin serves the administration endpoints of tsigoat over HTTP:
//
//	GET /healthz  200 while the process runs
//	GET /readyz   200 while tsigoat serves DNS, 503 otherwise
//	GET /metrics  Prometheus metrics
package admin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Timeouts of the HTTP server.
const (
	readTimeout  = 10 * time.Second
	writeTimeout = 30 * time.Second
)

// Server is the administration HTTP server.
type Server struct {
	server *http.Server
	done   chan error

	mu   sync.Mutex
	addr string
}

// New returns a server for the address. ready tells whether tsigoat serves
// DNS.
func New(address string, gatherer prometheus.Gatherer, ready func() bool) *Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		if !ready() {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = io.WriteString(w, "not ready\n")
			return
		}
		_, _ = io.WriteString(w, "ready\n")
	})
	mux.Handle("GET /metrics", promhttp.HandlerFor(gatherer, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	}))
	return &Server{server: &http.Server{
		Addr:              address,
		Handler:           mux,
		ReadHeaderTimeout: readTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
	}}
}

// Start listens, then serves in the background.
func (s *Server) Start(ctx context.Context) error {
	var config net.ListenConfig
	listener, err := config.Listen(ctx, "tcp", s.server.Addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.server.Addr, err)
	}
	s.mu.Lock()
	s.addr = listener.Addr().String()
	s.mu.Unlock()
	s.done = make(chan error, 1)
	go func() {
		err := s.server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		s.done <- err
	}()
	return nil
}

// Addr returns the address the server listens on, once started.
func (s *Server) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addr
}

// Done receives the error that stops the server, nil after Shutdown.
func (s *Server) Done() <-chan error {
	return s.done
}

// Shutdown stops the server, waiting for the requests in progress until ctx
// is done.
func (s *Server) Shutdown(ctx context.Context) error {
	if err := s.server.Shutdown(ctx); err != nil {
		return fmt.Errorf("stopping the administration server: %w", err)
	}
	return nil
}
