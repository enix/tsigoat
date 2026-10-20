//go:build live

// Package live runs tsigoat against real DNS providers, with the test zones
// and the credentials that a developer brings in a configuration file of
// tsigoat: see the section on live tests in CONTRIBUTING.md.
package live

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/app"
	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/backendtest"
	"github.com/enix/tsigoat/internal/backend/cloudflare/cloudflaretest"
	"github.com/enix/tsigoat/internal/backend/ovh/ovhtest"
	"github.com/enix/tsigoat/internal/backend/scaleway/scalewaytest"
	"github.com/enix/tsigoat/internal/config"
)

const (
	// label names the subtree of every test zone that the tests own.
	label = "tsigoat-test"
	// keyName names the key that the tests sign their updates with.
	keyName = "tsigoat-live-test."
)

// TestProviders runs, on every zone of the configuration, the conformance
// suite of the backends below tsigoat-test.<zone>, then the challenges of a
// certificate for that name and its wildcard, through tsigoat.
//
//nolint:paralleltest // one test at a time keeps within the rate limits of the providers
func TestProviders(t *testing.T) {
	path := os.Getenv("TSIGOAT_LIVE_CONFIG")
	if path == "" {
		t.Skip("TSIGOAT_LIVE_CONFIG is not set: run the live tests through `task test:live`, see CONTRIBUTING.md")
	}
	c, warnings, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, warning := range warnings {
		t.Logf("configuration warning: %s", warning)
	}
	tested := 0
	for i := range c.Zones {
		z := &c.Zones[i]
		entry := c.Backends[slices.IndexFunc(c.Backends, func(b config.Backend) bool { return b.Name == z.Backend })]
		e, known := expectations(entry.Type)
		if !known {
			t.Logf("zone %s: backend %s of type %s is not tested live", z.Name, entry.Name, entry.Type)
			continue
		}
		tested++
		t.Run(z.Name, func(t *testing.T) {
			b, err := app.NewBackend(&entry)
			if err != nil {
				t.Fatal(err)
			}
			suite := &backendtest.Suite{
				Backend:  b,
				Zone:     z.Name,
				Base:     label + "." + z.Name,
				Rejected: e.rejected,
				Failing:  e.failing,
			}
			t.Run("conformance", suite.Run)
			t.Run("acme", func(t *testing.T) { acme(t, c, z.Name, b) })
		})
	}
	if tested == 0 {
		t.Fatalf("%s holds no zone on a backend that the live tests know", path)
	}
}

// expectation is what the conformance suite expects of a type of backend.
type expectation struct {
	rejected map[string]string
	failing  func(name string) backend.Change
}

// expectations returns the expectations of a type of backend, and whether
// the live tests know it.
func expectations(backendType string) (expectation, bool) {
	switch backendType {
	case "powerdns":
		return expectation{failing: cnameBesideData}, true
	case "cloudflare":
		return expectation{rejected: cloudflaretest.Rejected(), failing: cloudflaretest.Failing}, true
	case "ovh":
		return expectation{rejected: ovhtest.Rejected(), failing: ovhtest.Failing}, true
	case "scaleway":
		return expectation{rejected: scalewaytest.Rejected(), failing: scalewaytest.Failing}, true
	default:
		return expectation{}, false
	}
}

// cnameBesideData returns a change that adds a CNAME record at a name that
// holds other data, which the providers refuse.
func cnameBesideData(name string) backend.Change {
	cname := &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "target.example.net."}
	return backend.Change{Op: backend.Replace, RRset: backend.RRset{Name: name, Type: dns.TypeCNAME, TTL: 300, Records: []dns.RR{cname}}}
}

// acme runs the challenges of a certificate for tsigoat-test.<zone> and its
// wildcard through tsigoat, as an ACME client does: two values at once,
// then the cleanup of each.
//
//nolint:thelper // the body of a subtest, whose failures point into it
func acme(t *testing.T, c *config.Config, zone string, b backend.Backend) {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	certificate := label + "." + zone
	live := &config.Config{
		Listen:   []string{"127.0.0.1:0"},
		Keys:     []config.Key{{Name: keyName, Algorithm: config.HMACSHA256, Secret: secret}},
		Backends: c.Backends,
		Zones: []config.Zone{{
			Name:    zone,
			Backend: c.Zones[slices.IndexFunc(c.Zones, func(z config.Zone) bool { return z.Name == zone })].Backend,
			Policy: []config.Rule{{
				Key: keyName, Names: []string{"_acme-challenge." + certificate}, Types: []string{"TXT"},
				MaxTTL: 300, Content: config.ACMEContent, MaxRecords: 10,
			}},
		}},
	}
	a, err := app.New(live, slog.New(slog.NewTextHandler(t.Output(), nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = a.Server.Shutdown(ctx)
	})
	addr := a.Server.Addrs()[0]
	name := "_acme-challenge." + certificate
	// A failed run may leave values behind, which the next one would find:
	// the name is cleared before the first update, and once the test is over.
	if err := clearChallenges(t.Context(), b, zone, name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(t.Context()), time.Minute)
		defer cancel()
		if err := clearChallenges(ctx, b, zone, name); err != nil {
			t.Errorf("cleaning up: %v", err)
		}
	})
	first, second := challengeValue(), challengeValue()

	update(t, addr, zone, secret, func(m *dns.Msg) { m.Insert([]dns.RR{txt(t, name, first)}) })
	expectValues(t, b, zone, name, first)
	update(t, addr, zone, secret, func(m *dns.Msg) { m.Insert([]dns.RR{txt(t, name, second)}) })
	expectValues(t, b, zone, name, first, second)
	update(t, addr, zone, secret, func(m *dns.Msg) { m.Remove([]dns.RR{txt(t, name, first)}) })
	expectValues(t, b, zone, name, second)
	update(t, addr, zone, secret, func(m *dns.Msg) { m.Remove([]dns.RR{txt(t, name, second)}) })
	expectValues(t, b, zone, name)
}

// clearChallenges deletes the TXT RRset of name.
func clearChallenges(ctx context.Context, b backend.Backend, zone, name string) error {
	change := backend.Change{Op: backend.Delete, RRset: backend.RRset{Name: name, Type: dns.TypeTXT}}
	if err := b.Apply(ctx, zone, []backend.Change{change}); err != nil {
		return fmt.Errorf("clearing %s: %w", name, err)
	}
	return nil
}

// challengeValue returns a random value of an ACME challenge: the base64url
// SHA-256 digest of a key authorization.
func challengeValue() string {
	authorization := make([]byte, 32)
	_, _ = rand.Read(authorization)
	digest := sha256.Sum256(authorization)
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func txt(t *testing.T, name, value string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(fmt.Sprintf("%s 60 IN TXT %q", name, value))
	if err != nil {
		t.Fatal(err)
	}
	return rr
}

// update sends a signed update of zone, which must succeed.
func update(t *testing.T, addr, zone string, secret []byte, build func(*dns.Msg)) {
	t.Helper()
	m := new(dns.Msg)
	m.SetUpdate(zone)
	build(m)
	m.SetTsig(keyName, dns.HmacSHA256, 300, time.Now().Unix())
	client := &dns.Client{Net: "tcp", Timeout: 30 * time.Second, TsigSecret: map[string]string{keyName: base64.StdEncoding.EncodeToString(secret)}}
	resp, _, err := client.ExchangeContext(t.Context(), m, addr)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("update answered %s", dns.RcodeToString[resp.Rcode])
	}
}

// expectValues checks that name holds exactly the TXT values.
func expectValues(t *testing.T, b backend.Backend, zone, name string, values ...string) {
	t.Helper()
	sets, err := b.Lookup(t.Context(), zone, name)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, set := range sets {
		for _, rr := range set.Records {
			if record, ok := rr.(*dns.TXT); ok {
				got = append(got, record.Txt...)
			}
		}
	}
	slices.Sort(got)
	want := slices.Sorted(slices.Values(values))
	if !slices.Equal(got, want) {
		t.Fatalf("%s holds %v, want %v", name, got, want)
	}
}
