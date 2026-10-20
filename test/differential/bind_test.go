//go:build differential

// Package differential runs the scenarios of test/scenario against BIND 9,
// the reference implementation of RFC 2136, to check what the scenarios
// expect. Where tsigoat departs from BIND on purpose, divergences.yaml says
// why, and the scenario must fail against BIND; any other failure is a
// scenario to fix, or a behavior of tsigoat to reconsider.
//
// The scenarios also run through tsigoat relaying to BIND: tsigoat checks the
// requests and their policy, BIND applies them, and every scenario must pass,
// divergences included.
//
// `task test:differential` runs it inside Dagger, which provides named and
// rndc.
package differential

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"go.yaml.in/yaml/v3"

	"github.com/enix/tsigoat/internal/app"
	"github.com/enix/tsigoat/internal/config"
	"github.com/enix/tsigoat/test/scenario"
)

const (
	// parent holds the zone of every scenario.
	parent = "bind.test."
	// relayParent holds the zones of the scenarios run through tsigoat.
	relayParent = "relayed.bind.test."
	// relayKeyName names the key that tsigoat signs with for BIND.
	relayKeyName = "relay."
)

func TestBIND(t *testing.T) {
	t.Parallel()

	scenarios := loadScenarios(t)
	divergences := loadDivergences(t)
	target := startBIND(t, scenarios, parent, updatePermissions)

	for _, s := range scenarios {
		if reason, ok := divergences[s.Name]; ok {
			s.KnownDefect = "divergence from BIND: " + reason
			delete(divergences, s.Name)
		}
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			scenario.Run(t, target, &s, parent)
		})
	}
	for name := range divergences {
		t.Errorf("divergences.yaml names an unknown scenario %q", name)
	}
}

// TestRelayToBIND runs every scenario through tsigoat, which relays the
// updates to BIND.
func TestRelayToBIND(t *testing.T) {
	t.Parallel()

	scenarios := loadScenarios(t)
	secret := randomSecret(t)
	relayOnly := func(*scenario.Zone) string {
		return fmt.Sprintf("update-policy { grant %q zonesub ANY; };", relayKeyName)
	}
	bind := startBIND(t, scenarios, relayParent, relayOnly,
		fmt.Sprintf("key %q { algorithm hmac-sha256; secret %q; };", relayKeyName, secret))
	target := &relayTarget{bindTarget: bind, addr: startRelay(t, scenarios, bind.addr, secret)}
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			scenario.Run(t, target, &s, relayParent)
		})
	}
}

// relayTarget is tsigoat relaying to BIND, whose zones it prepares and reads.
type relayTarget struct {
	*bindTarget
	addr string
}

func (r *relayTarget) Addr() string {
	return r.addr
}

// startRelay runs tsigoat in front of BIND until the end of the test, and
// returns its address.
func startRelay(t *testing.T, scenarios []scenario.Scenario, server, secret string) string {
	t.Helper()
	data, err := scenario.Config(scenarios, relayParent, scenario.RFC2136{Server: server, KeyName: relayKeyName, Secret: secret})
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := config.Parse(data, config.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c.Listen = []string{"127.0.0.1:0"}
	a, err := app.New(c, slog.New(slog.NewTextHandler(t.Output(), nil)), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Server.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := a.Server.Shutdown(ctx); err != nil {
			t.Errorf("shutting tsigoat down: %v", err)
		}
	})
	return a.Server.Addrs()[0]
}

func loadScenarios(t *testing.T) []scenario.Scenario {
	t.Helper()
	if _, err := exec.LookPath("named"); err != nil {
		t.Skip("named is not installed: run the differential tests through `task test:differential`")
	}
	scenarios, err := scenario.All()
	if err != nil {
		t.Fatal(err)
	}
	return scenarios
}

func loadDivergences(t *testing.T) map[string]string {
	t.Helper()
	data, err := os.ReadFile("divergences.yaml")
	if err != nil {
		t.Fatal(err)
	}
	divergences := map[string]string{}
	if err := yaml.Unmarshal(data, &divergences); err != nil {
		t.Fatalf("decoding divergences.yaml: %v", err)
	}
	return divergences
}

// bindTarget is a named process, whose zones the target creates with rndc.
type bindTarget struct {
	dir      string
	addr     string
	rndcConf string
	// zones holds the scenario zone of every zone name.
	zones map[string]*scenario.Zone
	// permissions returns the update permissions of a zone, as named.conf
	// writes them.
	permissions func(*scenario.Zone) string
	// rndc serializes the zone changes.
	rndc sync.Mutex
}

func (b *bindTarget) Addr() string {
	return b.addr
}

// ResetZone writes the zone file and adds the zone afresh, with its update
// permissions.
func (b *bindTarget) ResetZone(ctx context.Context, zone string, records []dns.RR) error {
	file := filepath.Join(b.dir, strings.TrimSuffix(zone, ".")+".db")
	var content strings.Builder
	// BIND refuses an in-zone NS without an address: ns1 gets one, which
	// Records leaves out.
	fmt.Fprintf(&content, "$ORIGIN %s\n$TTL 3600\n@ IN SOA ns1 hostmaster 1 10800 3600 604800 3600\n@ IN NS ns1\nns1 IN A %s\n",
		zone, nsAddress)
	for _, rr := range records {
		content.WriteString(rr.String() + "\n")
	}
	if err := os.WriteFile(file, []byte(content.String()), 0o600); err != nil {
		return err
	}
	_ = os.Remove(file + ".jnl")

	b.rndc.Lock()
	defer b.rndc.Unlock()
	_, _ = b.run(ctx, "delzone", zone)
	_ = os.Remove(file + ".jnl")
	// BIND checks that in-zone MX and SRV targets have addresses, which RFC
	// 2136 does not ask for.
	spec := fmt.Sprintf(`{ type primary; file %q; check-names ignore; check-integrity no; %s };`,
		file, b.permissions(b.zones[zone]))
	if output, err := b.run(ctx, "addzone", zone, spec); err != nil {
		return fmt.Errorf("rndc addzone %s: %w: %s", zone, err, output)
	}
	return nil
}

// updatePermissions returns the update permissions of a scenario zone: every
// key of the zone may update anything, and policy rules have no BIND
// equivalent.
func updatePermissions(z *scenario.Zone) string {
	if z == nil {
		return ""
	}
	if z.Unauthenticated {
		return "allow-update { any; };"
	}
	keys := z.Keys
	if len(keys) == 0 && len(z.Policy) == 0 {
		for _, key := range scenario.Keyring() {
			if key.Configured {
				keys = append(keys, key.ID)
			}
		}
	}
	if len(keys) == 0 {
		return ""
	}
	var grants strings.Builder
	for _, id := range keys {
		key, _ := scenario.KeyByID(id)
		fmt.Fprintf(&grants, "grant %q zonesub ANY; ", dns.Fqdn(key.ConfigName))
	}
	return "update-policy { " + grants.String() + "};"
}

func (b *bindTarget) run(ctx context.Context, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "rndc", append([]string{"-c", b.rndcConf}, args...)...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// Records reads the zone with a zone transfer.
func (b *bindTarget) Records(ctx context.Context, zone string) ([]dns.RR, error) {
	m := new(dns.Msg)
	m.SetAxfr(zone)
	transfer := &dns.Transfer{}
	envelopes, err := transfer.In(m, b.addr)
	if err != nil {
		return nil, err
	}
	var records []dns.RR
	for envelope := range envelopes {
		if envelope.Error != nil {
			return nil, envelope.Error
		}
		for _, rr := range envelope.RR {
			if rr.Header().Rrtype == dns.TypeSOA || isNSAddress(rr, zone) {
				continue
			}
			records = append(records, rr)
		}
	}
	_ = ctx
	return records, nil
}

// nsAddress is the address of the apex NS of the test zones.
const nsAddress = "192.0.2.53"

// isNSAddress reports the address record that ResetZone adds for the apex NS.
func isNSAddress(rr dns.RR, zone string) bool {
	a, ok := rr.(*dns.A)
	return ok && dns.CanonicalName(a.Hdr.Name) == "ns1."+zone && a.A.String() == nsAddress
}

// startBIND runs named with the test keyring and the extra key statements
// until the end of the test, for the scenarios under parent.
func startBIND(t *testing.T, scenarios []scenario.Scenario, parent string, permissions func(*scenario.Zone) string,
	extraKeys ...string,
) *bindTarget {
	t.Helper()
	dir := t.TempDir()
	dnsPort, controlPort := freePort(t), freePort(t)
	controlSecret := randomSecret(t)

	var conf strings.Builder
	fmt.Fprintf(&conf, `options {
	directory %q;
	listen-on port %d { 127.0.0.1; };
	listen-on-v6 { none; };
	allow-new-zones yes;
	recursion no;
	allow-transfer { any; };
	notify no;
	dnssec-validation no;
	pid-file %q;
	session-keyfile %q;
};
key "rndc-key" { algorithm hmac-sha256; secret %q; };
controls { inet 127.0.0.1 port %d allow { 127.0.0.1; } keys { "rndc-key"; }; };
logging { channel console { stderr; severity info; }; category default { console; }; };
`, dir, dnsPort, filepath.Join(dir, "named.pid"), filepath.Join(dir, "session.key"), controlSecret, controlPort)
	for _, key := range scenario.Keyring() {
		if !key.Configured {
			continue
		}
		algorithm := strings.TrimSuffix(strings.TrimSuffix(key.Algorithm, "."), ".sig-alg.reg.int")
		fmt.Fprintf(&conf, "key %q { algorithm %s; secret %q; };\n", dns.Fqdn(key.ConfigName), algorithm, key.Secret())
	}
	for _, key := range extraKeys {
		conf.WriteString(key + "\n")
	}
	namedConf := filepath.Join(dir, "named.conf")
	rndcConf := filepath.Join(dir, "rndc.conf")
	writeFile(t, namedConf, conf.String())
	writeFile(t, rndcConf, fmt.Sprintf(`key "rndc-key" { algorithm hmac-sha256; secret %q; };
options { default-key "rndc-key"; default-server 127.0.0.1; default-port %d; };
`, controlSecret, controlPort))

	logs := &bytes.Buffer{}
	var logsMu sync.Mutex
	cmd := exec.CommandContext(t.Context(), "named", "-g", "-c", namedConf)
	cmd.Stdout = lockedWriter{&logsMu, logs}
	cmd.Stderr = lockedWriter{&logsMu, logs}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting named: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			logsMu.Lock()
			t.Logf("named output:\n%s", logs)
			logsMu.Unlock()
		}
	})

	addr := fmt.Sprintf("127.0.0.1:%d", dnsPort)
	waitForTCP(t, addr)
	target := &bindTarget{dir: dir, addr: addr, rndcConf: rndcConf, zones: map[string]*scenario.Zone{}, permissions: permissions}
	for i := range scenarios {
		target.zones[scenarios[i].ZoneName(parent)] = &scenarios[i].Zone
	}
	return target
}

type lockedWriter struct {
	mu  *sync.Mutex
	buf *bytes.Buffer
}

func (w lockedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func randomSecret(t *testing.T) string {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(secret)
}

// freePort returns a loopback port free for both TCP and UDP.
func freePort(t *testing.T) int {
	t.Helper()
	var listenConfig net.ListenConfig
	for range 10 {
		listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		_ = listener.Close()
		packetConn, err := listenConfig.ListenPacket(t.Context(), "udp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		_ = packetConn.Close()
		return port
	}
	t.Fatal("no free port")
	return 0
}

func waitForTCP(t *testing.T, addr string) {
	t.Helper()
	dialer := net.Dialer{Timeout: time.Second}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := dialer.DialContext(t.Context(), "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("named is not listening on %s", addr)
}
