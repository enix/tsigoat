package app_test

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

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
