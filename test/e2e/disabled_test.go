//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/test/scenario"
)

// disabledTarget gives www an A RRset with a disabled record, right after the
// reset of the zone.
type disabledTarget struct {
	*pdnsTarget
}

func (d *disabledTarget) ResetZone(ctx context.Context, zone string, records []dns.RR) error {
	if err := d.pdnsTarget.ResetZone(ctx, zone, records); err != nil {
		return err
	}
	_, err := d.api.do(ctx, http.MethodPatch, "/zones/"+zone, map[string]any{"rrsets": []rrset{{
		Name: "www." + zone, Type: "A", TTL: new(uint32(300)), ChangeType: "REPLACE",
		Records: []record{{Content: "192.0.2.1"}, {Content: "192.0.2.9", Disabled: true}},
	}}}, nil)
	return err
}

// TestDisabledRecordsSurvive checks that an update of an RRset keeps its
// disabled records, which PowerDNS does not serve and tsigoat does not see.
// PowerDNS 4.9 leaves them out of the lookups of a name: tsigoat reads the
// whole zone there.
func TestDisabledRecordsSurvive(t *testing.T) {
	t.Parallel()

	env := newEnvironment(t)
	api := newPowerDNS(env.pdnsURL, env.pdnsAPIKey)

	s := scenario.Scenario{
		Name:        "backend/disabled-records",
		Description: "An update of an RRset keeps its disabled records.",
		Requests:    []scenario.Request{{Updates: []string{"add www 300 IN A 192.0.2.5"}}},
		// The records read back include the disabled one.
		Expect: scenario.Expect{Records: &[]string{
			"www 300 IN A 192.0.2.1", "www 300 IN A 192.0.2.5", "www 300 IN A 192.0.2.9",
		}},
	}
	tsigoat := startTsigoat(t, env, []scenario.Scenario{s}, env.pdns())
	scenario.Run(t, &disabledTarget{&pdnsTarget{api: api, addr: tsigoat.addr}}, &s, parentDomain)

	var content struct {
		RRsets []rrset `json:"rrsets"`
	}
	zone := s.ZoneName(parentDomain)
	if _, err := api.do(t.Context(), http.MethodGet, "/zones/"+zone, nil, &content); err != nil {
		t.Fatal(err)
	}
	for _, set := range content.RRsets {
		if set.Name != "www."+zone || set.Type != "A" {
			continue
		}
		for _, r := range set.Records {
			if r.Disabled != (r.Content == "192.0.2.9") {
				t.Errorf("record %s is disabled: %v", r.Content, r.Disabled)
			}
		}
	}
}
