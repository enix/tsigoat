//go:build e2e

package e2e

import (
	"bytes"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enix/tsigoat/test/scenario"
)

// environment holds the settings of the end-to-end tests, read from the
// environment.
type environment struct {
	// pdnsURL is the base URL of the PowerDNS HTTP API.
	pdnsURL string
	// pdnsAPIKey is the key of the PowerDNS HTTP API.
	pdnsAPIKey string
	// binary is a prebuilt tsigoat binary; the tests build one otherwise.
	binary string
	// toxiproxyURL is the API of a toxiproxy relaying the PowerDNS API on
	// proxiedPDNSURL, for the fault tests.
	toxiproxyURL   string
	proxiedPDNSURL string
}

// pdns returns the settings of the PowerDNS API.
func (e *environment) pdns() scenario.PowerDNS {
	return scenario.PowerDNS{URL: e.pdnsURL, APIKey: e.pdnsAPIKey}
}

func newEnvironment(t *testing.T) *environment {
	t.Helper()
	env := &environment{
		pdnsURL:    os.Getenv("TSIGOAT_E2E_PDNS_URL"),
		pdnsAPIKey: os.Getenv("TSIGOAT_E2E_PDNS_API_KEY"),
		binary:     os.Getenv("TSIGOAT_E2E_BINARY"),

		toxiproxyURL:   os.Getenv("TSIGOAT_E2E_TOXIPROXY_URL"),
		proxiedPDNSURL: os.Getenv("TSIGOAT_E2E_PROXIED_PDNS_URL"),
	}
	if env.pdnsURL == "" {
		t.Skip("TSIGOAT_E2E_PDNS_URL is not set: run the end-to-end tests through `task test:e2e`")
	}
	return env
}

// tsigoat is a running tsigoat process.
type tsigoat struct {
	addr string
	logs *syncBuffer
}

// startTsigoat runs tsigoat with a configuration that serves the zone of
// every scenario, until the end of the test.
func startTsigoat(t *testing.T, env *environment, scenarios []scenario.Scenario, pdns scenario.PowerDNS) *tsigoat {
	t.Helper()

	binary := env.binary
	if binary == "" {
		binary = buildTsigoat(t)
	}

	data, err := scenario.Config(scenarios, parentDomain, pdns)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(t.TempDir(), "tsigoat.yaml")
	if err := os.WriteFile(config, data, 0o600); err != nil {
		t.Fatal(err)
	}

	addr := freeAddress(t)
	logs := &syncBuffer{}
	// The test context ends right before the cleanup, which kills tsigoat.
	cmd := exec.CommandContext(t.Context(), binary, "serve",
		"--config", config,
		"--listen", addr,
		"--log-format", "json",
		"--log-level", "debug",
	)
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting tsigoat: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("tsigoat output (last lines):\n%s", logs.tail(200))
		}
	})

	waitForTCP(t, addr, logs)
	return &tsigoat{addr: addr, logs: logs}
}

func buildTsigoat(t *testing.T) string {
	t.Helper()
	binary := filepath.Join(t.TempDir(), "tsigoat")
	cmd := exec.CommandContext(t.Context(),
		"go", "build", "-o", binary, "github.com/enix/tsigoat/cmd/tsigoat")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building tsigoat: %v\n%s", err, output)
	}
	return binary
}

// freeAddress returns a loopback address whose port is free for both TCP and
// UDP. Another process may still grab it before tsigoat does, which is
// unlikely enough for tests.
func freeAddress(t *testing.T) string {
	t.Helper()
	var config net.ListenConfig
	for range 10 {
		listener, err := config.Listen(t.Context(), "tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		addr := listener.Addr().String()
		_ = listener.Close()

		packetConn, err := config.ListenPacket(t.Context(), "udp", addr)
		if err != nil {
			continue
		}
		_ = packetConn.Close()
		return addr
	}
	t.Fatal("no free port for both TCP and UDP")
	return ""
}

func waitForTCP(t *testing.T, addr string, logs *syncBuffer) {
	t.Helper()
	dialer := net.Dialer{Timeout: time.Second}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := dialer.DialContext(t.Context(), "tcp", addr)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("tsigoat is not listening on %s; output:\n%s", addr, logs.tail(50))
}

// syncBuffer collects the output of tsigoat.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns everything written.
func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// tail returns the last lines written.
func (b *syncBuffer) tail(lines int) string {
	b.mu.Lock()
	defer b.mu.Unlock()
	all := strings.Split(strings.TrimRight(b.buf.String(), "\n"), "\n")
	if len(all) > lines {
		all = append([]string{"... " + strconv.Itoa(len(all)-lines) + " lines skipped"}, all[len(all)-lines:]...)
	}
	return strings.Join(all, "\n")
}
