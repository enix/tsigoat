package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/tsigoat/internal/dagger"
)

// End-to-end fixtures. The TSIG secrets and the API key only exist inside
// the ephemeral Dagger network of a test run.
const (
	e2eZone         = "example.test."
	e2eKeyName      = "e2e."
	e2eKeySecret    = "c2VjcmV0LWZvci10aGUtZTJlLXRlc3RzLW9ubHktMzJi" // gitleaks:allow (throwaway)
	e2eMD5KeyName   = "e2e-md5."
	e2eMD5KeySecret = "bWQ1LXNlY3JldC1mb3ItdGhlLWUyZS10ZXN0cy0zMmI=" // gitleaks:allow (throwaway)
	e2eAPIKey       = "ZTJlLWFwaS1rZXk="                             // gitleaks:allow (throwaway)
	e2eDNSPort      = 5353
	pdnsDNSPort     = 5300
	pdnsAPIPort     = 8081
	toxiproxyPort   = 8474
	// proxiedAPIPort is where toxiproxy relays the PowerDNS API.
	proxiedAPIPort = 18081
)

// TestEndToEnd runs the scenarios of test/scenario against tsigoat placed in
// front of a PowerDNS server. The Go test suite builds tsigoat, runs it with a
// configuration serving the zone of every scenario, and checks the outcome
// of each scenario through the PowerDNS API. A toxiproxy between tsigoat and
// the PowerDNS API injects the faults of the fault tests.
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
	pdns := asPowerDNSService(server)

	return goBase(m.Source).
		WithExec([]string{"go", "install", "gotest.tools/gotestsum@" + gotestsumModule}).
		WithServiceBinding("pdns", pdns).
		WithServiceBinding("toxiproxy", toxiproxy(pdns)).
		WithEnvVariable("TSIGOAT_E2E_PDNS_URL", fmt.Sprintf("http://pdns:%d", pdnsAPIPort)).
		WithEnvVariable("TSIGOAT_E2E_PDNS_API_KEY", e2eAPIKey).
		WithEnvVariable("TSIGOAT_E2E_TOXIPROXY_URL", fmt.Sprintf("http://toxiproxy:%d", toxiproxyPort)).
		WithEnvVariable("TSIGOAT_E2E_PROXIED_PDNS_URL", fmt.Sprintf("http://toxiproxy:%d", proxiedAPIPort)).
		WithExec([]string{
			"gotestsum", "--format=testname", "--",
			"-tags=e2e", "-count=1", "./test/e2e/...",
		}).
		Stdout(ctx)
}

// TestClients runs real DNS clients against tsigoat. tsigoat is built from
// the source tree and placed in front of a PowerDNS server; a client
// container then sends TSIG-signed updates with nsupdate, with and without
// an explicit zone and with an HMAC-MD5 key, and checks through the PowerDNS
// API that the records landed in the zone. Everything runs inside the
// private Dagger network: no port is published on the host.
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
	return dag.Container().
		From(alpineImage).
		WithFile("/usr/local/bin/tsigoat", m.binary())
}

// binary returns tsigoat compiled from the source tree, for the platform of
// the engine.
func (m *Tsigoat) binary() *dagger.File {
	return goBase(m.Source).
		WithExec([]string{
			"go", "build", "-trimpath", "-tags", "osusergo,netgo",
			"-o", "/out/tsigoat", "./cmd/tsigoat",
		}).
		File("/out/tsigoat")
}

// toxiproxy returns a toxiproxy service that relays the PowerDNS API on
// proxiedAPIPort, under the proxy name "pdns-api". The proxy exists from the
// start, so that the port listens when Dagger checks it.
func toxiproxy(pdns *dagger.Service) *dagger.Service {
	config := fmt.Sprintf(`[{"name": "pdns-api", "listen": "0.0.0.0:%d", "upstream": "pdns:%d", "enabled": true}]`,
		proxiedAPIPort, pdnsAPIPort)
	return dag.Container().
		From(toxiproxyImage).
		WithServiceBinding("pdns", pdns).
		WithNewFile("/etc/toxiproxy.json", config).
		WithExposedPort(toxiproxyPort).
		WithExposedPort(proxiedAPIPort).
		AsService(dagger.ContainerAsServiceOpts{
			UseEntrypoint: true,
			Args:          []string{"-host=0.0.0.0", "-config=/etc/toxiproxy.json"},
		})
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

// e2eConfig renders the tsigoat configuration.
func e2eConfig() string {
	return fmt.Sprintf(`keys:
  - name: %s
    secret: %s
  - name: %s
    algorithm: hmac-md5
    secret: %s
backends:
  - name: pdns
    type: powerdns
    powerdns:
      url: http://pdns:%d
      apiKey: %s
zones:
  - name: %s
    keys: [%s, %s]
`, e2eKeyName, e2eKeySecret, e2eMD5KeyName, e2eMD5KeySecret, pdnsAPIPort, e2eAPIKey, e2eZone, e2eKeyName, e2eMD5KeyName)
}

// e2eSmokeScript creates the zone, sends signed updates with nsupdate and
// checks the result in PowerDNS. nsupdate fails unless tsigoat signs its
// responses.
func e2eSmokeScript() string {
	return strings.NewReplacer(
		"@ZONE@", e2eZone,
		"@KEY_NAME@", e2eKeyName,
		"@KEY_SECRET@", e2eKeySecret,
		"@MD5_KEY_NAME@", e2eMD5KeyName,
		"@MD5_KEY_SECRET@", e2eMD5KeySecret,
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

echo "== nsupdate, HMAC-SHA256, explicit zone"
nsupdate -y "hmac-sha256:@KEY_NAME@:@KEY_SECRET@" <<UPDATE
server $tsigoat_ip @DNS_PORT@
zone @ZONE@
update add _acme-challenge.@ZONE@ 60 TXT "smoke"
send
UPDATE

echo "== nsupdate, HMAC-SHA256, zone found with a SOA query, over TCP"
nsupdate -v -y "hmac-sha256:@KEY_NAME@:@KEY_SECRET@" <<UPDATE
server $tsigoat_ip @DNS_PORT@
update add _acme-challenge.www.@ZONE@ 60 TXT "discovered"
send
UPDATE

echo "== nsupdate, HMAC-MD5 key"
nsupdate -y "hmac-md5:@MD5_KEY_NAME@:@MD5_KEY_SECRET@" <<UPDATE
server $tsigoat_ip @DNS_PORT@
zone @ZONE@
update add md5.@ZONE@ 60 TXT "md5"
send
UPDATE

echo "== nsupdate, wrong algorithm for the key: must fail"
if nsupdate -y "hmac-sha512:@KEY_NAME@:@KEY_SECRET@" <<UPDATE
server $tsigoat_ip @DNS_PORT@
zone @ZONE@
update add wrong.@ZONE@ 60 TXT "wrong"
send
UPDATE
then
  echo "nsupdate accepted an update signed with the wrong algorithm" >&2
  exit 1
fi

echo "== check the records through the PowerDNS API"
records=$(curl -fsS -H "X-API-Key: @API_KEY@" "$api/zones/@ZONE@" \
  | jq -r '.rrsets[] | select(.type == "TXT") | "\(.name) \(.records[].content)"' | sort)
echo "$records"
expected=$(printf '%s\n' \
  '_acme-challenge.@ZONE@ "smoke"' \
  '_acme-challenge.www.@ZONE@ "discovered"' \
  'md5.@ZONE@ "md5"' | sort)
[ "$records" = "$expected" ]

echo "== check the record over DNS (UDP) on PowerDNS"
dig +short -p @PDNS_PORT@ @pdns "_acme-challenge.@ZONE@" TXT
echo "== OK"
`)
}

// TestDifferential runs the scenarios against BIND 9, the reference
// implementation of RFC 2136, to check what they expect; the scenarios where
// tsigoat departs from BIND on purpose are listed with their reason.
func (m *Tsigoat) TestDifferential(ctx context.Context) (string, error) {
	return goBase(m.Source).
		WithExec([]string{"apk", "add", "--no-cache", "bind"}).
		WithExec([]string{"go", "install", "gotest.tools/gotestsum@" + gotestsumModule}).
		WithExec([]string{
			"gotestsum", "--format=testname", "--",
			"-tags=differential", "-count=1", "./test/differential/...",
		}).
		Stdout(ctx)
}
