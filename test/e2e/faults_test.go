//go:build e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/enix/tsigoat/test/scenario"
)

// backendTimeout is the timeout of the calls to the PowerDNS API in the fault
// tests.
const backendTimeout = time.Second

// TestBackendFaults runs updates while toxiproxy disturbs the PowerDNS API:
// every one must fail with SERVFAIL within the timeout, and leave the zone
// unchanged. The faults share one proxy, so they run in turn.
func TestBackendFaults(t *testing.T) { //nolint:tparallel // the subtests share one proxy
	t.Parallel()

	env := newEnvironment(t)
	if env.toxiproxyURL == "" {
		t.Skip("TSIGOAT_E2E_TOXIPROXY_URL is not set: run the fault tests through `task test:e2e`")
	}
	// A large record makes the PATCH request much larger than the lookups.
	large := strings.Repeat("x", 200)
	update := "add www 60 IN TXT " + strings.Repeat(`"`+large+`" `, 10)
	failing := scenario.Scenario{
		Name:        "faults/backend",
		Description: "An update fails cleanly when the backend misbehaves.",
		Requests:    []scenario.Request{{Updates: []string{update}}},
		Expect:      scenario.Expect{Rcode: "SERVFAIL"},
	}
	working := failing
	working.Description = "An update succeeds once the backend recovers."
	working.Expect = scenario.Expect{Records: &[]string{`www 60 IN TXT "after"`}}
	working.Requests = []scenario.Request{{Updates: []string{`add www 60 IN TXT "after"`}}}

	pdns := scenario.PowerDNS{URL: env.proxiedPDNSURL, APIKey: env.pdnsAPIKey, Timeout: backendTimeout.String()}
	server := startTsigoat(t, env, []scenario.Scenario{failing}, pdns)
	// The zones are prepared and read directly, not through the proxy.
	target := &pdnsTarget{api: newPowerDNS(env.pdnsURL, env.pdnsAPIKey), addr: server.addr}
	proxy := &toxiproxy{url: env.toxiproxyURL, proxy: "pdns-api", client: &http.Client{Timeout: 10 * time.Second}}

	for _, fault := range []struct { //nolint:paralleltest // the subtests share one proxy
		name  string
		toxic map[string]any
		// failure is part of the error that tsigoat must log.
		failure string
	}{
		{"connection reset", map[string]any{
			"type": "reset_peer", "stream": "upstream", "attributes": map[string]any{"timeout": 0},
		}, "looking up"},
		{"API hanging", map[string]any{
			"type": "timeout", "stream": "upstream", "attributes": map[string]any{"timeout": 0},
		}, "looking up"},
		{"responses later than the timeout", map[string]any{
			"type": "latency", "stream": "downstream", "attributes": map[string]any{"latency": 3000},
		}, "looking up"},
		{"connection cut in the middle of the PATCH", map[string]any{
			"type": "limit_data", "stream": "upstream", "attributes": map[string]any{"bytes": 1500},
		}, "applying the changes"},
	} {
		t.Run(fault.name, func(t *testing.T) {
			if err := proxy.addToxic(t.Context(), fault.toxic); err != nil {
				t.Fatal(err)
			}
			logged := len(server.logs.String())
			start := time.Now()
			scenario.Run(t, target, &failing, parentDomain)
			if elapsed := time.Since(start); elapsed > 3*backendTimeout {
				t.Errorf("the update took %s, more than the backend timeout allows", elapsed)
			}
			if logs := server.logs.String()[logged:]; !strings.Contains(logs, fault.failure) {
				t.Errorf("tsigoat did not log a failure %q:\n%s", fault.failure, logs)
			}

			if err := proxy.removeToxic(t.Context()); err != nil {
				t.Fatal(err)
			}
			scenario.Run(t, target, &working, parentDomain)
		})
	}
}

// toxiproxy drives a proxy of toxiproxy through its HTTP API.
type toxiproxy struct {
	url    string
	proxy  string
	client *http.Client
}

const toxicName = "fault"

func (p *toxiproxy) addToxic(ctx context.Context, toxic map[string]any) error {
	toxic["name"] = toxicName
	return p.call(ctx, http.MethodPost, "/proxies/"+p.proxy+"/toxics", toxic)
}

func (p *toxiproxy) removeToxic(ctx context.Context) error {
	return p.call(ctx, http.MethodDelete, "/proxies/"+p.proxy+"/toxics/"+toxicName, nil)
}

func (p *toxiproxy) call(ctx context.Context, method, path string, body any) error {
	api := &powerDNS{base: p.url, client: p.client}
	_, err := api.do(ctx, method, path, body, nil)
	if err != nil {
		return fmt.Errorf("toxiproxy: %w", err)
	}
	return nil
}
