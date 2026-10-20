package admin_test

import (
	"context"
	"io"
	"net/http"
	"strings"
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

	server := admin.New("127.0.0.1:0", registry, ready.Load)
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
	server := admin.New("256.0.0.1:1", prometheus.NewRegistry(), func() bool { return true })
	if err := server.Start(t.Context()); err == nil {
		t.Error("Start() succeeded on an invalid address")
	}
	if server.Addr() != "" {
		t.Errorf("Addr() = %q after a failed start", server.Addr())
	}
}
