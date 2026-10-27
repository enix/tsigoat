package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/tsigoat/internal/dagger"
)

// ACME fixtures. The secrets only exist inside the ephemeral Dagger network of
// a test run.
const (
	acmeZone          = "acme.test."
	acmeLegoKey       = "lego."
	acmeLegoSecret    = "bGVnby1zZWNyZXQtZm9yLXRoZS1hY21lLXRlc3RzLTMyYg==" // gitleaks:allow (throwaway)
	acmeCertbotKey    = "certbot."
	acmeCertbotSecret = "Y2VydGJvdC1zZWNyZXQtZm9yLXRoZS1hY21lLXRlc3RzMzI=" // gitleaks:allow (throwaway)
	pebblePort        = 14000
	pebbleCAPath      = "/test/certs/pebble.minica.pem"
)

// TestACME runs the whole ACME DNS-01 flow with real clients: lego and
// certbot obtain certificates from Pebble, a test ACME server, solving their
// challenges through tsigoat, while Pebble checks the challenges on PowerDNS.
// Both clients must get their certificate and clean their records up.
func (m *Tsigoat) TestACME(
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
		WithNewFile("/etc/tsigoat/config.yaml", acmeConfig()).
		WithExposedPort(e2eDNSPort, dagger.ContainerWithExposedPortOpts{Protocol: dagger.NetworkProtocolTcp}).
		WithExposedPort(e2eDNSPort, dagger.ContainerWithExposedPortOpts{Protocol: dagger.NetworkProtocolUdp}).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"/usr/local/bin/tsigoat", "serve", "--log-level", "debug"},
		})
	pebble := dag.Container().
		From(pebbleImage).
		WithServiceBinding("pdns", pdns).
		// No random sleeps nor nonce rejections: a quick and steady test.
		WithEnvVariable("PEBBLE_VA_NOSLEEP", "1").
		WithEnvVariable("PEBBLE_WFE_NONCEREJECT", "0").
		WithExposedPort(pebblePort).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"/app", "-config", "test/config/pebble-config.json", "-dnsserver", fmt.Sprintf("pdns:%d", pdnsDNSPort)},
		})
	pebbleCA := dag.Container().From(pebbleImage).File(pebbleCAPath)
	directory := fmt.Sprintf("https://pebble:%d/dir", pebblePort)

	// Dagger stops a service once the containers that need it are done: keep
	// them up across the steps, which run in separate containers.
	for _, service := range []*dagger.Service{pdns, tsigoat, pebble} {
		started, err := service.Start(ctx)
		if err != nil {
			return "", fmt.Errorf("starting a service: %w", err)
		}
		defer func() { _, _ = started.Stop(context.WithoutCancel(ctx)) }()
	}

	var report strings.Builder
	steps := []struct {
		name      string
		container *dagger.Container
	}{
		{"create zone " + acmeZone, apiClient(pdns).WithExec([]string{"sh", "-euc", fmt.Sprintf(
			`curl -fsS -X POST -H "X-API-Key: %s" -H "Content-Type: application/json" `+
				`-d '{"name": "%s", "kind": "Native", "nameservers": ["ns1.%s"]}' http://pdns:%d/api/v1/servers/localhost/zones >/dev/null`,
			e2eAPIKey, acmeZone, acmeZone, pdnsAPIPort)})},
		{"lego", dag.Container().
			From(legoImage).
			WithServiceBinding("pdns", pdns).
			WithServiceBinding("tsigoat", tsigoat).
			WithServiceBinding("pebble", pebble).
			WithFile("/pebble-ca.pem", pebbleCA).
			WithEnvVariable("LEGO_CA_CERTIFICATES", "/pebble-ca.pem").
			WithEnvVariable("DNSUPDATE_NAMESERVER", fmt.Sprintf("tsigoat:%d", e2eDNSPort)).
			WithEnvVariable("DNSUPDATE_TSIG_KEY", acmeLegoKey).
			WithEnvVariable("DNSUPDATE_TSIG_SECRET", acmeLegoSecret).
			WithEnvVariable("DNSUPDATE_TSIG_ALGORITHM", "hmac-sha256.").
			WithExec([]string{
				"/lego", "run", "--accept-tos", "--email", "acme@example.test", "--server", directory,
				"--path", "/data", "--domains", "lego." + strings.TrimSuffix(acmeZone, "."),
				"--dns", "dnsupdate", "--dns.resolvers", fmt.Sprintf("pdns:%d", pdnsDNSPort),
				// PowerDNS serves an update at once; the authoritative
				// servers of the zone have no address in the test network.
				"--dns.propagation.wait", "1s",
			}).
			WithExec([]string{"/bin/sh", "-c", "ls /data/certificates/lego.acme.test.crt"})},
		{"certbot", dag.Container().
			From(certbotImage).
			WithServiceBinding("pdns", pdns).
			WithServiceBinding("tsigoat", tsigoat).
			WithServiceBinding("pebble", pebble).
			WithFile("/pebble-ca.pem", pebbleCA).
			WithEnvVariable("REQUESTS_CA_BUNDLE", "/pebble-ca.pem").
			WithExec([]string{"sh", "-euc", certbotScript(directory)})},
		{"check that the challenges are gone", apiClient(pdns).WithExec([]string{"sh", "-euc", fmt.Sprintf(
			`left=$(curl -fsS -H "X-API-Key: %s" http://pdns:%d/api/v1/servers/localhost/zones/%s | `+
				`jq -r '.rrsets[] | select(.name | startswith("_acme-challenge")) | .name')
			[ -z "$left" ] || { echo "challenge records left: $left" >&2; exit 1; }`,
			e2eAPIKey, pdnsAPIPort, acmeZone)})},
	}
	for _, step := range steps {
		output, err := step.container.Stdout(ctx)
		if err != nil {
			return report.String(), fmt.Errorf("%s: %w", step.name, err)
		}
		fmt.Fprintf(&report, "== %s\n%s", step.name, output)
	}
	return report.String() + "== OK\n", nil
}

// apiClient returns a container with curl and jq, bound to PowerDNS.
func apiClient(pdns *dagger.Service) *dagger.Container {
	return dag.Container().
		From(alpineImage).
		WithExec([]string{"apk", "add", "--no-cache", "curl", "jq"}).
		WithServiceBinding("pdns", pdns)
}

// acmeConfig renders the configuration of tsigoat for the ACME clients, each
// restricted to the challenges of its certificate.
func acmeConfig() string {
	return fmt.Sprintf(`keys:
  - name: %[1]s
    secret: %[2]s
  - name: %[3]s
    secret: %[4]s
backends:
  - name: pdns
    type: powerdns
    powerdns:
      url: http://pdns:%[5]d
      apiKey: %[6]s
zones:
  - name: %[7]s
    policy:
      - key: %[1]s
        acme: [lego.%[7]s]
      - key: %[3]s
        acme: [certbot.%[7]s]
`, acmeLegoKey, acmeLegoSecret, acmeCertbotKey, acmeCertbotSecret, pdnsAPIPort, e2eAPIKey, acmeZone)
}

// certbotScript writes the credentials of the dns-rfc2136 plugin, which
// wants the address of tsigoat rather than its name, and runs certbot. The
// plugin sends its SOA queries unsigned, as by default.
func certbotScript(directory string) string {
	return strings.NewReplacer(
		"@KEY@", acmeCertbotKey,
		"@SECRET@", acmeCertbotSecret,
		"@PORT@", fmt.Sprint(e2eDNSPort),
		"@DIRECTORY@", directory,
		"@DOMAIN@", "certbot."+strings.TrimSuffix(acmeZone, "."),
	).Replace(`
cat > /tsigoat.ini <<INI
dns_rfc2136_server = $(getent hosts tsigoat | awk '{ print $1; exit }')
dns_rfc2136_port = @PORT@
dns_rfc2136_name = @KEY@
dns_rfc2136_secret = @SECRET@
dns_rfc2136_algorithm = HMAC-SHA256
INI
chmod 600 /tsigoat.ini
certbot certonly --non-interactive --agree-tos --email acme@example.test \
  --server @DIRECTORY@ --dns-rfc2136 --dns-rfc2136-credentials /tsigoat.ini \
  --dns-rfc2136-propagation-seconds 1 --domains @DOMAIN@
ls /etc/letsencrypt/live/@DOMAIN@/fullchain.pem
`)
}
