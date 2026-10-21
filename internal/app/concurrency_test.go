package app_test

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/memory"
	"github.com/enix/tsigoat/internal/config"
)

// slowLookups delays the lookups of a backend, which widens the time between
// the reads of an update and its writes, where the updates of another
// instance come. It keeps the TTL floor of the backend.
type slowLookups struct {
	backend.Backend
	floor uint32
}

func (s slowLookups) Lookup(ctx context.Context, zone, name string) ([]backend.RRset, error) {
	time.Sleep(5 * time.Millisecond)
	return s.Backend.Lookup(ctx, zone, name)
}

func (s slowLookups) MinTTL() uint32 {
	return s.floor
}

// TestConcurrentInstances runs two instances of tsigoat on one backend, as the
// replicas of a Deployment do: the updates of one name that come at once,
// through either instance, must all apply, those that add values as those
// that remove them. Each instance serializes the updates of a zone alone; the
// backends apply the records that an update adds and removes to the records
// as they stand. The records have a TTL below the minimum of the providers,
// which the server raises before it tells an addition from a replacement.
func TestConcurrentInstances(t *testing.T) {
	t.Parallel()
	const zone, name, count = "example.test.", "_acme-challenge.example.test.", 16
	type target struct {
		name  string
		start func(t *testing.T) backend.Backend
	}
	targets := make([]target, 0, 4)
	targets = append(targets, target{name: "memory", start: func(t *testing.T) backend.Backend {
		t.Helper()
		b := memory.New()
		b.SetZone(zone,
			mustRR(t, zone+" 3600 IN SOA ns1."+zone+" hostmaster."+zone+" 1 7200 900 1209600 300"),
			mustRR(t, zone+" 3600 IN NS ns1."+zone),
		)
		return b
	}})
	for _, p := range providers() {
		targets = append(targets, target{name: p.name, start: func(t *testing.T) backend.Backend {
			t.Helper()
			simulation, b := p.start(t)
			simulation.createZone(zone)
			return b
		}})
	}

	for _, target := range targets {
		t.Run(target.name, func(t *testing.T) {
			t.Parallel()
			b := slowLookups{Backend: target.start(t)}
			if floor, ok := b.Backend.(backend.TTLFloor); ok {
				b.floor = floor.MinTTL()
			}
			factory := func(*config.Backend) (backend.Backend, error) { return b, nil }
			instances := []string{serve(t, minimalConfig(t), factory), serve(t, minimalConfig(t), factory)}
			values := make([]string, count)
			for i := range values {
				values[i] = fmt.Sprintf("challenge-%02d", i)
			}

			// send sends one update per value, at once, to either instance.
			send := func(add bool) {
				var wg sync.WaitGroup
				for i, value := range values {
					wg.Go(func() {
						m := new(dns.Msg)
						m.SetUpdate(zone)
						record := mustRR(t, fmt.Sprintf("%s 30 IN TXT %q", name, value))
						if add {
							m.Insert([]dns.RR{record})
						} else {
							m.Remove([]dns.RR{record})
						}
						m.SetTsig("key.example.", dns.HmacSHA256, 300, time.Now().Unix())
						client := &dns.Client{Net: "tcp", TsigSecret: map[string]string{"key.example.": minimalSecret}}
						resp, _, err := client.ExchangeContext(t.Context(), m, instances[i%len(instances)])
						if err != nil || resp.Rcode != dns.RcodeSuccess {
							t.Errorf("update of %s: %v %v", value, resp, err)
						}
					})
				}
				wg.Wait()
			}
			held := func() []string {
				sets, err := b.Lookup(t.Context(), zone, name)
				if err != nil {
					t.Fatal(err)
				}
				var got []string
				for _, set := range sets {
					for _, rr := range set.Records {
						if txt, ok := rr.(*dns.TXT); ok {
							got = append(got, txt.Txt...)
						}
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
		})
	}
}
