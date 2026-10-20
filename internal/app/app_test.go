package app_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/app"
	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/memory"
	"github.com/enix/tsigoat/internal/config"
)

const minimal = `
keys:
  - name: key.example.
    secret: MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= # gitleaks:allow (fixture)
backends:
  - name: pdns
    type: powerdns
    powerdns:
      url: http://127.0.0.1:1
      apiKey: unused
zones:
  - name: example.test.
    keys: [key.example.]
`

// minimalConfig returns a configuration listening on a free port.
func minimalConfig(t *testing.T) *config.Config {
	t.Helper()
	c, _, err := config.Parse([]byte(minimal), config.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c.Listen = []string{"127.0.0.1:0"}
	return c
}

func TestNewAndRun(t *testing.T) {
	t.Parallel()

	logs := &strings.Builder{}
	logger := slog.New(slog.NewTextHandler(logs, nil))
	a, err := app.New(minimalConfig(t), logger, func(*config.Backend) (backend.Backend, error) {
		return memory.New(), nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// The zone is missing from the backend: a warning, not a failure.
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if err := a.Run(ctx); err != nil {
		t.Errorf("Run() = %v", err)
	}
	if !strings.Contains(logs.String(), `msg="zone check failed"`) || !strings.Contains(logs.String(), "backend pdns") {
		t.Errorf("no warning about the missing zone in the logs:\n%s", logs)
	}
}

func TestNewErrors(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	failing := func(*config.Backend) (backend.Backend, error) { return nil, errors.New("injected") }
	if _, err := app.New(minimalConfig(t), logger, failing); err == nil || !strings.Contains(err.Error(), "backend pdns: injected") {
		t.Errorf("New() with a failing backend: %v", err)
	}

	c := minimalConfig(t)
	c.Backends[0].PowerDNS.URL = "not a URL"
	if _, err := app.New(c, logger, nil); err == nil {
		t.Error("New() accepted an invalid PowerDNS URL")
	}

	c = minimalConfig(t)
	c.Backends[0].Type = "other"
	if _, err := app.NewBackend(&c.Backends[0]); err == nil {
		t.Error("NewBackend() accepted an unknown type")
	}

	c = minimalConfig(t)
	c.Zones[0].Backend = "missing"
	if _, err := app.New(c, logger, nil); err == nil {
		t.Error("New() accepted a zone with an unknown backend")
	}
}

func TestNewBackend(t *testing.T) {
	t.Parallel()

	c := minimalConfig(t)
	b, err := app.NewBackend(&c.Backends[0])
	if err != nil {
		t.Fatal(err)
	}
	// Nothing listens on port 1.
	if _, err := b.Lookup(t.Context(), "example.test.", "example.test."); err == nil {
		t.Error("Lookup() succeeded without a PowerDNS server")
	}
}

func httpGet(t *testing.T, url string) (status int, body string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, url, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(data)
}

func TestAdminServer(t *testing.T) {
	t.Parallel()

	c := minimalConfig(t)
	c.AdminListen = "127.0.0.1:0"
	a, err := app.New(c, slog.New(slog.DiscardHandler), func(*config.Backend) (backend.Backend, error) {
		return memory.New(), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- a.Run(ctx) }()

	deadline := time.Now().Add(5 * time.Second)
	for {
		if addr := a.AdminAddr(); addr != "" {
			if status, _ := httpGet(t, "http://"+addr+"/readyz"); status == http.StatusOK {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("tsigoat did not get ready")
		}
		time.Sleep(10 * time.Millisecond)
	}

	m := new(dns.Msg)
	m.SetQuestion("www.example.test.", dns.TypeA)
	client := &dns.Client{Timeout: 2 * time.Second}
	resp, _, err := client.ExchangeContext(t.Context(), m, a.Server.Addrs()[0])
	if err != nil || resp.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("A query: %v, %v", resp, err)
	}

	want := `tsigoat_dns_responses_total{algorithm="",key="",opcode="QUERY",rcode="NOTIMP",zone="example.test."} 1`
	if status, body := httpGet(t, "http://"+a.AdminAddr()+"/metrics"); status != http.StatusOK || !strings.Contains(body, want) {
		t.Errorf("/metrics = %d, without %s:\n%s", status, want, body)
	}

	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run() = %v", err)
	}
}

// flooredBackend is an in-memory backend with a minimum TTL.
type flooredBackend struct {
	*memory.Backend
}

func (flooredBackend) MinTTL() uint32 {
	return 60
}

// TestTTLFloor checks that the zones of a backend with a minimum TTL get it,
// with the metrics on, which wrap the backend.
func TestTTLFloor(t *testing.T) {
	t.Parallel()

	b := memory.New()
	b.SetZone("example.test.",
		mustRR(t, "example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 1 7200 900 1209600 300"),
		mustRR(t, "example.test. 3600 IN NS ns1.example.test."),
	)
	c := minimalConfig(t)
	c.AdminListen = "127.0.0.1:0"
	c.Zones[0].AllowUnauthenticated = true
	a, err := app.New(c, slog.New(slog.DiscardHandler), func(*config.Backend) (backend.Backend, error) {
		return flooredBackend{b}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if startErr := a.Server.Start(t.Context()); startErr != nil {
		t.Fatal(startErr)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if shutdownErr := a.Server.Shutdown(ctx); shutdownErr != nil {
			t.Errorf("shutting down: %v", shutdownErr)
		}
	})

	m := new(dns.Msg)
	m.SetUpdate("example.test.")
	m.Insert([]dns.RR{mustRR(t, `www.example.test. 0 IN TXT "zero"`)})
	resp, err := dns.ExchangeContext(t.Context(), m, a.Server.Addrs()[0])
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("rcode %s, want NOERROR", dns.RcodeToString[resp.Rcode])
	}
	sets, err := b.Lookup(t.Context(), "example.test.", "www.example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 1 || sets[0].TTL != 60 {
		t.Errorf("Lookup() = %v, want the TTL raised to 60", sets)
	}
}

func mustRR(t *testing.T, text string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(text)
	if err != nil {
		t.Fatal(err)
	}
	return rr
}
