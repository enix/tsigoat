//go:build e2e

package e2e

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/backendtest"
	"github.com/enix/tsigoat/internal/backend/powerdns"
)

// TestBackendConformance runs the conformance suite of the backends on the
// PowerDNS backend.
func TestBackendConformance(t *testing.T) {
	t.Parallel()
	env := newEnvironment(t)

	const zone = "conformance.test."
	if err := newPowerDNS(env.pdnsURL, env.pdnsAPIKey).resetZone(t.Context(), zone); err != nil {
		t.Fatal(err)
	}
	b, err := powerdns.New(&powerdns.Options{URL: env.pdnsURL, APIKey: env.pdnsAPIKey})
	if err != nil {
		t.Fatal(err)
	}
	suite := &backendtest.Suite{
		Backend: b,
		Zone:    zone,
		Base:    "suite." + zone,
		// PowerDNS refuses a CNAME beside other data.
		Failing: func(name string) backend.Change {
			cname := &dns.CNAME{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300}, Target: "target.example.net."}
			return backend.Change{Op: backend.Replace, RRset: backend.RRset{Name: name, Type: dns.TypeCNAME, TTL: 300, Records: []dns.RR{cname}}}
		},
	}
	suite.Run(t)
}
