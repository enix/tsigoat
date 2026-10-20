package main

import (
	"dagger/tsigoat/internal/dagger"
)

// DevBackend returns a PowerDNS server that already serves the example.test.
// zone, for the local development loop:
//
//	dagger call dev-backend --api-key=... up --ports 8081:8081,5300:5300
func (m *Tsigoat) DevBackend(
	// Key of the PowerDNS HTTP API.
	apiKey string,
	// PowerDNS release line: "4.9" or "5.0".
	// +optional
	// +default="5.0"
	pdnsVersion string,
) (*dagger.Service, error) {
	server, err := powerDNS(pdnsVersion, apiKey)
	if err != nil {
		return nil, err
	}
	server = server.WithExec([]string{"pdnsutil", "create-zone", "example.test", "ns1.example.test"})
	return asPowerDNSService(server), nil
}
