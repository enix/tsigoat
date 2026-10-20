package cloudflare_test

import (
	"testing"

	"github.com/enix/tsigoat/internal/backend/backendtest"
	"github.com/enix/tsigoat/internal/backend/cloudflare"
	"github.com/enix/tsigoat/internal/backend/cloudflare/cloudflaretest"
)

const testZone = "example.test."

// newBackend returns a backend on a simulated API that holds testZone.
func newBackend(t *testing.T) (*cloudflare.Backend, *cloudflaretest.API, string) {
	t.Helper()
	api := cloudflaretest.New(t)
	id := api.CreateZone(testZone, "ns1.example.test.", "ns2.example.test.")
	b, err := cloudflare.New(&cloudflare.Options{URL: api.URL, APIToken: cloudflaretest.Token})
	if err != nil {
		t.Fatal(err)
	}
	return b, api, id
}

// TestConformance runs the conformance suite of the backends on the
// simulated API.
func TestConformance(t *testing.T) {
	t.Parallel()
	b, _, _ := newBackend(t)
	suite := &backendtest.Suite{
		Backend:  b,
		Zone:     testZone,
		Base:     "conformance." + testZone,
		Rejected: cloudflaretest.Rejected(),
		Failing:  cloudflaretest.Failing,
	}
	suite.Run(t)
}
