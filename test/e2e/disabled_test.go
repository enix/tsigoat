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
// disabled records, which PowerDNS does not serve and tsigoat does not see,
// even when it removes every record that clients see. PowerDNS 4.9 leaves
// them out of the lookups of a name: tsigoat reads the whole zone there.
// EXTEND and PRUNE drop them: tsigoat puts them back.
func TestDisabledRecordsSurvive(t *testing.T) {
	t.Parallel()

	env := newEnvironment(t)
	api := newPowerDNS(env.pdnsURL, env.pdnsAPIKey)
	scenarios := []scenario.Scenario{
		{
			Name:        "backend/disabled-records-added",
			Description: "An update that adds a record keeps the disabled records of its RRset.",
			Requests:    []scenario.Request{{Updates: []string{"add www 300 IN A 192.0.2.5"}}},
			// The records read back include the disabled one.
			Expect: scenario.Expect{Records: &[]string{
				"www 300 IN A 192.0.2.1", "www 300 IN A 192.0.2.5", "www 300 IN A 192.0.2.9",
			}},
		},
		{
			Name:        "backend/disabled-records-replaced",
			Description: "An update that changes the TTL of an RRset keeps its disabled records.",
			Requests:    []scenario.Request{{Updates: []string{"add www 600 IN A 192.0.2.5"}}},
			Expect: scenario.Expect{Records: &[]string{
				"www 600 IN A 192.0.2.1", "www 600 IN A 192.0.2.5", "www 600 IN A 192.0.2.9",
			}},
		},
		{
			Name:        "backend/disabled-records-removed",
			Description: "An update that deletes every record that clients see keeps the disabled ones.",
			Requests:    []scenario.Request{{Updates: []string{"delete www A"}}},
			Expect:      scenario.Expect{Records: &[]string{"www 300 IN A 192.0.2.9"}},
		},
	}
	tsigoat := startTsigoat(t, env, scenarios, env.pdns())
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
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
		})
	}
}
