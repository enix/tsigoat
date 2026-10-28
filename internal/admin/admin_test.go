package admin_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/enix/tsigoat/internal/admin"
)

func get(t *testing.T, url string) (status int, body string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(data)
}

func TestServer(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	counter := prometheus.NewCounter(prometheus.CounterOpts{Name: "test_total", Help: "A test counter."})
	registry.MustRegister(counter)
	counter.Inc()
	var ready atomic.Bool

	server := admin.New("127.0.0.1:0", registry, ready.Load, slog.New(slog.DiscardHandler))
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	base := "http://" + server.Addr()

	if status, body := get(t, base+"/healthz"); status != http.StatusOK || body != "ok\n" {
		t.Errorf("/healthz = %d %q", status, body)
	}
	if status, _ := get(t, base+"/readyz"); status != http.StatusServiceUnavailable {
		t.Errorf("/readyz before ready = %d, want 503", status)
	}
	ready.Store(true)
	if status, _ := get(t, base+"/readyz"); status != http.StatusOK {
		t.Errorf("/readyz once ready = %d, want 200", status)
	}
	if status, body := get(t, base+"/metrics"); status != http.StatusOK || !strings.Contains(body, "test_total 1") {
		t.Errorf("/metrics = %d %q", status, body)
	}
	if status, _ := get(t, base+"/nowhere"); status != http.StatusNotFound {
		t.Errorf("/nowhere = %d, want 404", status)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-server.Done(); err != nil {
		t.Errorf("Done() = %v after Shutdown()", err)
	}
}

func TestStartError(t *testing.T) {
	t.Parallel()
	server := admin.New("256.0.0.1:1", prometheus.NewRegistry(), func() bool { return true }, slog.New(slog.DiscardHandler))
	if err := server.Start(t.Context()); err == nil {
		t.Error("Start() succeeded on an invalid address")
	}
	if server.Addr() != "" {
		t.Errorf("Addr() = %q after a failed start", server.Addr())
	}
}

// lockedBuffer is a buffer that the server and the test share.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// failingCollector is a collector whose metric fails.
type failingCollector struct {
	desc *prometheus.Desc
}

func (c failingCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c failingCollector) Collect(ch chan<- prometheus.Metric) {
	ch <- prometheus.NewInvalidMetric(c.desc, errors.New("injected failure"))
}

// TestErrorsInTheLog checks that the errors of the metrics go to the log of
// tsigoat, at the error level, rather than nowhere, and those of the HTTP
// server too, rather than to the standard error.
func TestErrorsInTheLog(t *testing.T) {
	t.Parallel()

	logs := &lockedBuffer{}
	registry := prometheus.NewRegistry()
	registry.MustRegister(failingCollector{desc: prometheus.NewDesc("test_failing", "A failing metric.", nil, nil)})
	// The readiness of a broken build panics, which net/http recovers.
	panics := func() bool { panic("readiness broken") }
	server := admin.New("127.0.0.1:0", registry, panics, slog.New(slog.NewJSONHandler(logs, nil)))
	if err := server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})

	get(t, "http://"+server.Addr()+"/metrics")
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+server.Addr()+"/readyz", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := http.DefaultClient.Do(req); err == nil {
		_ = resp.Body.Close()
	}
	for _, want := range []string{`"level":"ERROR"`, `"server":"admin"`, "injected failure", "readiness broken"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("log %q, without %s", logs.String(), want)
		}
	}
}
