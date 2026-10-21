//go:build e2e

package e2e

import (
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/test/scenario"
)

// TestConcurrentInstances runs two tsigoat processes on one PowerDNS, as the
// replicas of a Deployment do: the challenges of one name that come at once,
// through either process, must all apply, then all go. Each process
// serializes the updates of a zone alone; PowerDNS applies the records that
// an update adds and removes to the records as they stand.
func TestConcurrentInstances(t *testing.T) {
	t.Parallel()

	env := newEnvironment(t)
	api := newPowerDNS(env.pdnsURL, env.pdnsAPIKey)
	s := scenario.Scenario{Name: "backend/concurrent-instances"}
	zone := s.ZoneName(parentDomain)
	if err := api.resetZone(t.Context(), zone); err != nil {
		t.Fatal(err)
	}
	instances := []*tsigoat{
		startTsigoat(t, env, []scenario.Scenario{s}, env.pdns()),
		startTsigoat(t, env, []scenario.Scenario{s}, env.pdns()),
	}
	key, _ := scenario.KeyByID(scenario.DefaultKey)
	name := "_acme-challenge." + zone
	values := make([]string, 16)
	for i := range values {
		values[i] = fmt.Sprintf("challenge-%02d", i)
	}

	// send sends one update per value, at once, to either process.
	send := func(add bool) {
		var wg sync.WaitGroup
		for i, value := range values {
			wg.Go(func() {
				record, err := dns.NewRR(fmt.Sprintf("%s 60 IN TXT %q", name, value))
				if err != nil {
					t.Error(err)
					return
				}
				m := new(dns.Msg)
				m.SetUpdate(zone)
				if add {
					m.Insert([]dns.RR{record})
				} else {
					m.Remove([]dns.RR{record})
				}
				m.SetTsig(key.Name, key.Algorithm, 300, time.Now().Unix())
				client := &dns.Client{Net: "tcp", Timeout: 10 * time.Second, TsigSecret: map[string]string{key.Name: key.Secret()}}
				resp, _, err := client.ExchangeContext(t.Context(), m, instances[i%len(instances)].addr)
				if err != nil || resp.Rcode != dns.RcodeSuccess {
					t.Errorf("update of %s: %v %v", value, resp, err)
				}
			})
		}
		wg.Wait()
	}
	held := func() []string {
		records, err := api.records(t.Context(), zone)
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, rr := range records {
			if txt, ok := rr.(*dns.TXT); ok && dns.CanonicalName(txt.Hdr.Name) == name {
				got = append(got, txt.Txt...)
			}
		}
		slices.Sort(got)
		return got
	}

	send(true)
	if got := held(); !slices.Equal(got, values) {
		t.Errorf("after the additions, %s holds %v, want %v", name, got, values)
	}
	send(false)
	if got := held(); len(got) != 0 {
		t.Errorf("after the removals, %s holds %v, want nothing", name, got)
	}
}
