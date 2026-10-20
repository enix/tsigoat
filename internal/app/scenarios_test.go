package app_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/app"
	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/memory"
	"github.com/enix/tsigoat/internal/config"
	"github.com/enix/tsigoat/test/scenario"
)

// parent holds the zone of every scenario.
const parent = "scenarios.test."

// memoryTarget is tsigoat in front of the in-memory backend.
type memoryTarget struct {
	backend *memory.Backend
	addr    string
}

func (m *memoryTarget) Addr() string {
	return m.addr
}

func (m *memoryTarget) ResetZone(_ context.Context, zone string, records []dns.RR) error {
	apex, err := scenario.ParseRecords([]string{
		"@ 3600 IN SOA ns1 hostmaster 1 10800 3600 604800 3600",
		"@ 3600 IN NS ns1",
	}, zone)
	if err != nil {
		return err
	}
	m.backend.SetZone(zone, append(apex, records...)...)
	return nil
}

func (m *memoryTarget) Records(_ context.Context, zone string) ([]dns.RR, error) {
	records, err := m.backend.Records(zone)
	if err != nil {
		return nil, err
	}
	content := records[:0]
	for _, rr := range records {
		if rr.Header().Rrtype != dns.TypeSOA {
			content = append(content, rr)
		}
	}
	return content, nil
}

// start runs tsigoat with the configuration of the scenarios, on the
// in-memory backend.
func start(t *testing.T, scenarios []scenario.Scenario) *memoryTarget {
	t.Helper()

	data, err := scenario.Config(scenarios, parent, scenario.PowerDNS{URL: "http://unused.invalid", APIKey: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := config.Parse(data, config.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c.Listen = []string{"127.0.0.1:0"}

	b := memory.New()
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
	a, err := app.New(c, logger, func(*config.Backend) (backend.Backend, error) { return b, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.Server.Shutdown(ctx); err != nil {
			t.Errorf("shutting down: %v", err)
		}
	})
	return &memoryTarget{backend: b, addr: a.Server.Addrs()[0]}
}

// TestScenarios runs every scenario in-process, on the in-memory backend.
func TestScenarios(t *testing.T) {
	t.Parallel()

	scenarios, err := scenario.All()
	if err != nil {
		t.Fatal(err)
	}
	target := start(t, scenarios)
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			scenario.Run(t, target, &s, parent)
		})
	}
}
