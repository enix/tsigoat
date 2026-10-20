//go:build e2e

// Package e2e runs the scenarios of test/scenario against tsigoat placed in
// front of a real PowerDNS server.
//
// `task test:e2e` runs it inside Dagger, and `task test:e2e:dev` against the
// development backend of `task dev`. Both set TSIGOAT_E2E_PDNS_URL and
// TSIGOAT_E2E_PDNS_API_KEY.
package e2e

import (
	"testing"

	"github.com/enix/tsigoat/test/scenario"
)

// parentDomain holds the zone of every scenario.
const parentDomain = "e2e.test."

func TestScenarios(t *testing.T) {
	t.Parallel()

	env := newEnvironment(t)
	scenarios, err := scenario.All()
	if err != nil {
		t.Fatal(err)
	}

	api := newPowerDNS(env.pdnsURL, env.pdnsAPIKey)
	server := startTsigoat(t, env, scenarios, env.pdns())
	target := &pdnsTarget{api: api, addr: server.addr}

	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			scenario.Run(t, target, &s, parentDomain)
		})
	}
}
