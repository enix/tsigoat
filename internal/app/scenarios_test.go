package app_test

import (
	"context"
	"encoding/base64"
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

const (
	// parent holds the zone of every scenario.
	parent = "scenarios.test."
	// relayedParent holds the zones of the scenarios run through a relay.
	relayedParent = "relayed.test."
	// relayKeyName names the key that a relaying tsigoat signs with.
	relayKeyName = "relay."
)

// relaySecret is the secret of the relay key.
var relaySecret = []byte("thirty-two bytes of relay secret")

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

// serve runs tsigoat with a configuration until the end of the test, and
// returns its address.
func serve(t *testing.T, c *config.Config, newBackend app.BackendFactory) string {
	t.Helper()
	c.Listen = []string{"127.0.0.1:0"}
	logger := slog.New(slog.NewTextHandler(t.Output(), &slog.HandlerOptions{Level: slog.LevelDebug}))
	a, err := app.New(c, logger, newBackend)
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
	return a.Server.Addrs()[0]
}

// scenarioConfig parses the configuration of the scenarios on a backend.
func scenarioConfig(t *testing.T, scenarios []scenario.Scenario, parent string, b scenario.Backend) *config.Config {
	t.Helper()
	data, err := scenario.Config(scenarios, parent, b)
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := config.Parse(data, config.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// onMemory builds every backend on b.
func onMemory(b *memory.Backend) app.BackendFactory {
	return func(*config.Backend) (backend.Backend, error) { return b, nil }
}

// TestScenarios runs every scenario in-process, on the in-memory backend.
func TestScenarios(t *testing.T) {
	t.Parallel()

	scenarios, err := scenario.All()
	if err != nil {
		t.Fatal(err)
	}
	b := memory.New()
	c := scenarioConfig(t, scenarios, parent, scenario.PowerDNS{URL: "http://unused.invalid", APIKey: "unused"})
	target := &memoryTarget{backend: b, addr: serve(t, c, onMemory(b))}
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			scenario.Run(t, target, &s, parent)
		})
	}
}

// TestScenariosRelayed runs every scenario through a tsigoat that relays the
// updates to another tsigoat, on the in-memory backend: the first one checks
// the requests and their policy, the second one evaluates and applies them.
// The outcome must not change.
func TestScenariosRelayed(t *testing.T) {
	t.Parallel()

	scenarios, err := scenario.All()
	if err != nil {
		t.Fatal(err)
	}
	b := memory.New()
	server := serve(t, relayedServerConfig(scenarios), onMemory(b))
	c := scenarioConfig(t, scenarios, relayedParent, scenario.RFC2136{
		Server:  server,
		KeyName: relayKeyName,
		Secret:  base64.StdEncoding.EncodeToString(relaySecret),
	})
	target := &memoryTarget{backend: b, addr: serve(t, c, nil)}
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			scenario.Run(t, target, &s, relayedParent)
		})
	}
}

// relayedServerConfig lets the relay key update every record of the zones of
// the scenarios, the SOA included: the relaying tsigoat enforces the policy.
func relayedServerConfig(scenarios []scenario.Scenario) *config.Config {
	c := &config.Config{
		Keys:     []config.Key{{Name: relayKeyName, Algorithm: config.HMACSHA256, Secret: relaySecret}},
		Backends: []config.Backend{{Name: "memory", Type: "memory"}},
	}
	for i := range scenarios {
		zone := scenarios[i].ZoneName(relayedParent)
		c.Zones = append(c.Zones, config.Zone{Name: zone, Backend: "memory", Policy: []config.Rule{
			{Key: relayKeyName, Names: []string{zone, "**." + zone}},
			{Key: relayKeyName, Names: []string{zone}, Types: []string{"SOA"}},
		}})
	}
	return c
}
