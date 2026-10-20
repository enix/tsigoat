package app_test

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/cloudflare"
	"github.com/enix/tsigoat/internal/backend/cloudflare/cloudflaretest"
	"github.com/enix/tsigoat/internal/backend/ovh"
	"github.com/enix/tsigoat/internal/backend/ovh/ovhtest"
	"github.com/enix/tsigoat/internal/backend/scaleway"
	"github.com/enix/tsigoat/internal/backend/scaleway/scalewaytest"
	"github.com/enix/tsigoat/internal/config"
	"github.com/enix/tsigoat/test/scenario"
)

// providerParent holds the zones of the scenarios run on the simulated APIs
// of the hosted providers.
const providerParent = "provider.test."

// simulation is the simulated API of a hosted provider, which a backend of
// tsigoat writes to.
type simulation interface {
	// createZone creates a zone afresh, with the NS records of the apex.
	createZone(zone string)
	// names returns the canonical names of the records of a zone.
	names(zone string) []string
}

// providerTarget is tsigoat in front of the simulated API of a provider: the
// backend writes the records of the scenarios and reads them back.
type providerTarget struct {
	addr       string
	backend    backend.Backend
	simulation simulation
}

func (p *providerTarget) Addr() string {
	return p.addr
}

func (p *providerTarget) ResetZone(ctx context.Context, zone string, records []dns.RR) error {
	p.simulation.createZone(zone)
	var changes []backend.Change
	for _, rr := range records {
		h := rr.Header()
		name := dns.CanonicalName(h.Name)
		i := slices.IndexFunc(changes, func(c backend.Change) bool { return c.RRset.Name == name && c.RRset.Type == h.Rrtype })
		if i < 0 {
			changes = append(changes, backend.Change{Op: backend.Replace, RRset: backend.RRset{Name: name, Type: h.Rrtype, TTL: h.Ttl}})
			i = len(changes) - 1
		}
		changes[i].RRset.Records = append(changes[i].RRset.Records, rr)
	}
	if len(changes) == 0 {
		return nil
	}
	return p.backend.Apply(ctx, zone, changes)
}

func (p *providerTarget) Records(ctx context.Context, zone string) ([]dns.RR, error) {
	names := append([]string{zone}, p.simulation.names(zone)...)
	slices.Sort(names)
	var records []dns.RR
	for _, name := range slices.Compact(names) {
		sets, err := p.backend.Lookup(ctx, zone, name)
		if err != nil {
			return nil, err
		}
		for _, set := range sets {
			if set.Type != dns.TypeSOA {
				records = append(records, set.Records...)
			}
		}
	}
	return records, nil
}

// cloudflareSimulation is the simulated API of Cloudflare.
type cloudflareSimulation struct {
	api *cloudflaretest.API
	mu  sync.Mutex
	ids map[string]string
}

func (c *cloudflareSimulation) createZone(zone string) {
	id := c.api.CreateZone(zone, "ns1."+zone)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ids[zone] = id
}

func (c *cloudflareSimulation) names(zone string) []string {
	c.mu.Lock()
	id := c.ids[zone]
	c.mu.Unlock()
	records := c.api.Records(id)
	names := make([]string, 0, len(records))
	for _, r := range records {
		names = append(names, dns.CanonicalName(r.Name))
	}
	return names
}

type ovhSimulation struct {
	api *ovhtest.API
}

func (o *ovhSimulation) createZone(zone string) {
	o.api.CreateZone(zone)
}

func (o *ovhSimulation) names(zone string) []string {
	records := o.api.Records(zone)
	names := make([]string, 0, len(records))
	for _, r := range records {
		names = append(names, below(r.SubDomain, zone))
	}
	return names
}

type scalewaySimulation struct {
	api *scalewaytest.API
}

func (s *scalewaySimulation) createZone(zone string) {
	s.api.CreateZone(zone)
}

func (s *scalewaySimulation) names(zone string) []string {
	records := s.api.Records(zone)
	names := make([]string, 0, len(records))
	for i := range records {
		names = append(names, below(records[i].Name, zone))
	}
	return names
}

// below returns the canonical name of a name relative to a zone, "" for its
// apex.
func below(relative, zone string) string {
	if relative == "" {
		return zone
	}
	return dns.CanonicalName(relative + "." + zone)
}

// provider is a hosted provider that the scenarios run on.
type provider struct {
	name string
	// start starts the simulated API, and returns it with the backend that
	// writes to it.
	start func(t *testing.T) (simulation, backend.Backend)
	// divergences lists the scenarios that fail on the provider on purpose,
	// with the reason.
	divergences map[string]string
}

func providers() []provider {
	return []provider{
		{
			name: "cloudflare",
			start: func(t *testing.T) (simulation, backend.Backend) {
				t.Helper()
				api := cloudflaretest.New(t)
				b, err := cloudflare.New(&cloudflare.Options{URL: api.URL, APIToken: cloudflaretest.Token})
				if err != nil {
					t.Fatal(err)
				}
				return &cloudflareSimulation{api: api, ids: map[string]string{}}, b
			},
			divergences: cloudflaretest.Divergences(),
		},
		{
			name: "ovh",
			start: func(t *testing.T) (simulation, backend.Backend) {
				t.Helper()
				api := ovhtest.New(t)
				b, err := ovh.New(&ovh.Options{
					Endpoint:       api.URL,
					ApplicationKey: ovhtest.ApplicationKey, ApplicationSecret: ovhtest.ApplicationSecret, ConsumerKey: ovhtest.ConsumerKey,
				})
				if err != nil {
					t.Fatal(err)
				}
				return &ovhSimulation{api: api}, b
			},
			divergences: ovhtest.Divergences(),
		},
		{
			name: "scaleway",
			start: func(t *testing.T) (simulation, backend.Backend) {
				t.Helper()
				api := scalewaytest.New(t)
				b, err := scaleway.New(&scaleway.Options{URL: api.URL, SecretKey: scalewaytest.SecretKey})
				if err != nil {
					t.Fatal(err)
				}
				return &scalewaySimulation{api: api}, b
			},
			divergences: scalewaytest.Divergences(),
		},
	}
}

// TestScenariosOnProviders runs every scenario on the simulated API of each
// hosted provider. The scenarios that a provider fails on purpose, such as
// those of record types that it does not hold, are listed with the reason:
// they must fail, and a failure that is not listed fails the test.
func TestScenariosOnProviders(t *testing.T) {
	t.Parallel()
	scenarios, err := scenario.All()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range providers() {
		t.Run(p.name, func(t *testing.T) {
			t.Parallel()
			simulation, b := p.start(t)
			c := scenarioConfig(t, scenarios, providerParent, scenario.PowerDNS{URL: "http://unused.invalid", APIKey: "unused"})
			target := &providerTarget{
				backend:    b,
				simulation: simulation,
				addr:       serve(t, c, func(*config.Backend) (backend.Backend, error) { return b, nil }),
			}
			divergences := maps.Clone(p.divergences)
			for _, s := range scenarios {
				if reason, ok := divergences[s.Name]; ok {
					s.KnownDefect = fmt.Sprintf("divergence on %s: %s", p.name, reason)
					delete(divergences, s.Name)
				}
				t.Run(s.Name, func(t *testing.T) {
					t.Parallel()
					scenario.Run(t, target, &s, providerParent)
				})
			}
			for name := range divergences {
				t.Errorf("the divergences of %s name an unknown scenario %q", p.name, name)
			}
		})
	}
}
