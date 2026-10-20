//go:build e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/test/scenario"
)

// serialTarget records the SOA serial of the zone right after its reset.
type serialTarget struct {
	*pdnsTarget
	before uint32
}

func (s *serialTarget) ResetZone(ctx context.Context, zone string, records []dns.RR) error {
	if err := s.pdnsTarget.ResetZone(ctx, zone, records); err != nil {
		return err
	}
	serial, err := s.api.serial(ctx, zone)
	s.before = serial
	return err
}

// TestSOASerialIncrements checks that PowerDNS bumps the serial of a zone
// updated through tsigoat, as SOA-EDIT-API does for the zones created through
// the API.
func TestSOASerialIncrements(t *testing.T) {
	t.Parallel()

	env := newEnvironment(t)
	s := scenario.Scenario{
		Name:        "backend/soa-serial",
		Description: "An update bumps the serial of the zone.",
		Requests:    []scenario.Request{{Updates: []string{`add www 60 IN TXT "serial"`}}},
		Expect:      scenario.Expect{Records: &[]string{`www 60 IN TXT "serial"`}},
	}
	server := startTsigoat(t, env, []scenario.Scenario{s})
	api := newPowerDNS(env.pdnsURL, env.pdnsAPIKey)
	target := &serialTarget{pdnsTarget: &pdnsTarget{api: api, addr: server.addr}}

	scenario.Run(t, target, &s, parentDomain)

	after, err := api.serial(t.Context(), s.ZoneName(parentDomain))
	if err != nil {
		t.Fatal(err)
	}
	if after <= target.before {
		t.Errorf("serial %d after the update, %d before: SOA-EDIT-API did not bump it", after, target.before)
	}
}

// serial returns the SOA serial of a zone.
func (p *powerDNS) serial(ctx context.Context, zone string) (uint32, error) {
	var content struct {
		RRsets []rrset `json:"rrsets"`
	}
	if _, err := p.do(ctx, http.MethodGet, "/zones/"+zone, nil, &content); err != nil {
		return 0, err
	}
	for _, set := range content.RRsets {
		if set.Type != "SOA" || len(set.Records) == 0 {
			continue
		}
		rr, err := dns.NewRR(fmt.Sprintf("%s %d IN SOA %s", set.Name, set.TTL, set.Records[0].Content))
		if err != nil {
			return 0, fmt.Errorf("parsing the SOA of %s: %w", zone, err)
		}
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Serial, nil
		}
	}
	return 0, errors.New("no SOA in zone " + zone)
}
