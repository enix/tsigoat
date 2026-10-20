package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/tsigoat/internal/dagger"
)

// End-to-end fixtures. The TSIG secret and the API key only exist inside the
// ephemeral Dagger network of a test run.
const (
	e2eZone      = "example.test."
	e2eKeyName   = "e2e."
	e2eKeySecret = "c2VjcmV0LWZvci10aGUtZTJlLXRlc3RzLW9ubHktMzJi" // gitleaks:allow (throwaway)
	e2eAPIKey    = "ZTJlLWFwaS1rZXk="                             // gitleaks:allow (throwaway)
	e2eDNSPort   = 5353
	pdnsDNSPort  = 5300
	pdnsAPIPort  = 8081
)

// TestEndToEnd runs the scenarios of test/scenario against tsigoat placed in
// front of a PowerDNS server. The Go test suite builds tsigoat, runs it with a
// configuration serving the zone of every scenario, and checks the outcome
// of each scenario through the PowerDNS API.
func (m *Tsigoat) TestEndToEnd(
	ctx context.Context,
	// PowerDNS release line to test against: "4.9" or "5.0".
	// +optional
	// +default="5.0"
	pdnsVersion string,
) (string, error) {
	server, err := powerDNS(pdnsVersion, e2eAPIKey)
	if err != nil {
		return "", err
	}

	return goBase(m.Source).
		WithExec([]string{"go", "install", "gotest.tools/gotestsum@" + gotestsumModule}).
		WithServiceBinding("pdns", asPowerDNSService(server)).
		WithEnvVariable("TSIGOAT_E2E_PDNS_URL", fmt.Sprintf("http://pdns:%d", pdnsAPIPort)).
		WithEnvVariable("TSIGOAT_E2E_PDNS_API_KEY", e2eAPIKey).
		WithExec([]string{
			"gotestsum", "--format=testname", "--",
			"-tags=e2e", "-count=1", "./test/e2e/...",
		}).
		Stdout(ctx)
}

// TestClients runs real DNS clients against tsigoat. tsigoat is built from
// the source tree and placed in front of a PowerDNS server; a client
// container then sends a TSIG-signed update with nsupdate and checks, through
// the PowerDNS API, that the record landed in the zone. Everything runs
// inside the private Dagger network: no port is published on the host.
func (m *Tsigoat) TestClients(
	ctx context.Context,
	// PowerDNS release line to test against: "4.9" or "5.0".
	// +optional
	// +default="5.0"
	pdnsVersion string,
) (string, error) {
	pdnsServer, err := powerDNS(pdnsVersion, e2eAPIKey)
	if err != nil {
		return "", err
	}
	pdns := asPowerDNSService(pdnsServer)

	tsigoat := m.e2eImage().
		WithServiceBinding("pdns", pdns).
		WithNewFile("/etc/tsigoat/tsigoat.yaml", e2eConfig()).
		WithExposedPort(e2eDNSPort, dagger.ContainerWithExposedPortOpts{Protocol: dagger.NetworkProtocolTcp}).
		WithExposedPort(e2eDNSPort, dagger.ContainerWithExposedPortOpts{Protocol: dagger.NetworkProtocolUdp}).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{
				"/usr/local/bin/tsigoat", "serve",
				"--config", "/etc/tsigoat/tsigoat.yaml",
				"--log-format", "json",
				"--log-level", "debug",
			},
		})

	return dag.Container().
		From(alpineImage).
		WithExec([]string{"apk", "add", "--no-cache", "bind-tools", "curl", "jq"}).
		WithServiceBinding("pdns", pdns).
		WithServiceBinding("tsigoat", tsigoat).
		WithNewFile("/e2e/smoke.sh", e2eSmokeScript()).
		WithExec([]string{"sh", "/e2e/smoke.sh"}).
		Stdout(ctx)
}

// e2eImage returns a runtime container with tsigoat compiled from the source
// tree.
func (m *Tsigoat) e2eImage() *dagger.Container {
	binary := goBase(m.Source).
		WithExec([]string{
			"go", "build", "-trimpath", "-tags", "osusergo,netgo",
			"-o", "/out/tsigoat", "./cmd/tsigoat",
		}).
		File("/out/tsigoat")

	return dag.Container().
		From(alpineImage).
		WithFile("/usr/local/bin/tsigoat", binary)
}

// powerDNS returns a PowerDNS authoritative server with its HTTP API enabled.
func powerDNS(version, apiKey string) (*dagger.Container, error) {
	image, err := pdnsImageFor(version)
	if err != nil {
		return nil, err
	}
	return dag.Container().
		From(image).
		WithEnvVariable("PDNS_AUTH_API_KEY", apiKey), nil
}

// asPowerDNSService starts a PowerDNS container as a service. The image runs
// as a non-root user, which cannot bind port 53 inside Dagger, hence the
// unprivileged DNS port.
func asPowerDNSService(server *dagger.Container) *dagger.Service {
	return server.
		WithExposedPort(pdnsDNSPort, dagger.ContainerWithExposedPortOpts{Protocol: dagger.NetworkProtocolTcp}).
		WithExposedPort(pdnsDNSPort, dagger.ContainerWithExposedPortOpts{Protocol: dagger.NetworkProtocolUdp}).
		WithExposedPort(pdnsAPIPort).
		AsService(dagger.ContainerAsServiceOpts{
			UseEntrypoint: true,
			Args:          []string{fmt.Sprintf("--local-port=%d", pdnsDNSPort)},
		})
}

func pdnsImageFor(version string) (string, error) {
	switch version {
	case "4.9":
		return pdns49Image, nil
	case "5.0":
		return pdns50Image, nil
	default:
		return "", fmt.Errorf("unsupported PowerDNS version %q (expected 4.9 or 5.0)", version)
	}
}

// e2eConfig renders the tsigoat configuration, in the legacy format that the
// current code understands.
func e2eConfig() string {
	return fmt.Sprintf(`tsig:
  keys:
    - name: %s
      key: %s
      default: true
handlers:
  - name: pdns
    adapter: powerdns
    default: true
    powerdns:
      url: http://pdns:%d
      vhost: localhost
      key: %s
zones:
  - zone: %s
`, e2eKeyName, e2eKeySecret, pdnsAPIPort, e2eAPIKey, e2eZone)
}

// e2eSmokeScript creates the zone, sends a signed update and checks the
// result in PowerDNS. nsupdate's verdict is reported but does not fail the
// run: the legacy server does not sign its responses (defect P7).
func e2eSmokeScript() string {
	return strings.NewReplacer(
		"@ZONE@", e2eZone,
		"@KEY_NAME@", e2eKeyName,
		"@KEY_SECRET@", e2eKeySecret,
		"@API_KEY@", e2eAPIKey,
		"@DNS_PORT@", fmt.Sprint(e2eDNSPort),
		"@API_PORT@", fmt.Sprint(pdnsAPIPort),
		"@PDNS_PORT@", fmt.Sprint(pdnsDNSPort),
	).Replace(`set -eu
api="http://pdns:@API_PORT@/api/v1/servers/localhost"

echo "== create zone @ZONE@ in PowerDNS"
curl -fsS -X POST -H "X-API-Key: @API_KEY@" -H "Content-Type: application/json" \
  -d '{"name": "@ZONE@", "kind": "Native", "nameservers": ["ns1.@ZONE@"]}' \
  "$api/zones" > /dev/null

tsigoat_ip=$(getent hosts tsigoat | awk '{ print $1; exit }')
echo "== tsigoat resolves to $tsigoat_ip"

echo "== send a TSIG-signed update with nsupdate"
cat > /tmp/update.txt <<UPDATE
server $tsigoat_ip @DNS_PORT@
zone @ZONE@
update add _acme-challenge.@ZONE@ 60 TXT "smoke"
send
UPDATE
set +e
nsupdate -y "hmac-sha256:@KEY_NAME@:@KEY_SECRET@" /tmp/update.txt
status=$?
set -e
echo "== nsupdate exit status: $status"

echo "== check the record through the PowerDNS API"
content=$(curl -fsS -H "X-API-Key: @API_KEY@" "$api/zones/@ZONE@" \
  | jq -r '.rrsets[] | select(.name == "_acme-challenge.@ZONE@" and .type == "TXT") | .records[].content')
echo "TXT content: $content"
[ "$content" = '"smoke"' ]

echo "== check the record over DNS (UDP) on PowerDNS"
dig +short -p @PDNS_PORT@ @pdns "_acme-challenge.@ZONE@" TXT
echo "== OK"
`)
}
