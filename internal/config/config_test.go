package config_test

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/enix/tsigoat/internal/config"
)

// testOptions resolve the secrets of the fixtures, which never hold any.
func testOptions() config.Options {
	env := map[string]string{
		// 32 bytes, base64-encoded.
		"TSIGOAT_TEST_SECRET":  "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0LCB0aGlydHktdHdvIQ==",
		"TSIGOAT_TEST_API_KEY": "test-api-key",
	}
	return config.Options{
		LookupEnv: func(name string) (string, bool) {
			value, ok := env[name]
			return value, ok
		},
		ReadFile: os.ReadFile,
	}
}

// TestFixtures is a ratchet: every file of test/config/valid must load, and
// every file of test/config/invalid must fail with an error containing each
// line of its .expect.txt companion. Loosening a check means editing a
// fixture, which a reviewer sees.
func TestFixtures(t *testing.T) {
	t.Parallel()

	for _, path := range fixtures(t, "../../test/config/valid/*.yaml") {
		t.Run("valid/"+filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, parseErr := config.Parse(data, testOptions()); parseErr != nil {
				t.Errorf("Parse() failed: %v", parseErr)
			}
		})
	}

	for _, path := range fixtures(t, "../../test/config/invalid/*.yaml") {
		t.Run("invalid/"+filepath.Base(path), func(t *testing.T) {
			t.Parallel()
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			expect, err := os.ReadFile(strings.TrimSuffix(path, ".yaml") + ".expect.txt")
			if err != nil {
				t.Fatalf("missing the .expect.txt companion: %v", err)
			}

			_, _, err = config.Parse(data, testOptions())
			if err == nil {
				t.Fatal("Parse() succeeded, want an error")
			}
			for line := range strings.SplitSeq(string(expect), "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if !strings.Contains(err.Error(), line) {
					t.Errorf("error does not contain %q:\n%v", line, err)
				}
			}
		})
	}
}

func fixtures(t *testing.T, pattern string) []string {
	t.Helper()
	paths, err := filepath.Glob(pattern)
	if err != nil || len(paths) == 0 {
		t.Fatalf("no fixture matches %s: %v", pattern, err)
	}
	return paths
}

func TestParseFull(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../test/config/valid/full.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, warnings, err := config.Parse(data, testOptions())
	if err != nil {
		t.Fatal(err)
	}

	if got, want := c.Listen, []string{"[::]:5353", "127.0.0.1:10053"}; !slices.Equal(got, want) {
		t.Errorf("Listen = %q, want %q", got, want)
	}

	wantKeys := []struct {
		name      string
		algorithm config.Algorithm
	}{
		{"cert-manager.", config.HMACSHA512},
		{"admin.", config.HMACSHA256},
		{"legacy-dhcp.", config.HMACMD5},
	}
	for i, want := range wantKeys {
		if c.Keys[i].Name != want.name || c.Keys[i].Algorithm != want.algorithm {
			t.Errorf("Keys[%d] = %s %s, want %s %s", i, c.Keys[i].Name, c.Keys[i].Algorithm, want.name, want.algorithm)
		}
	}
	if got := string(c.Keys[1].Secret); got != "this is not a secret at all!" {
		t.Errorf("secret read from the file = %q", got)
	}

	pdns := c.Backends[0].PowerDNS
	if pdns.URL != "https://pdns.example.test:8081" || pdns.ServerID != "localhost" ||
		pdns.APIKey != "test-api-key" || pdns.Timeout != 2*time.Second {
		t.Errorf("PowerDNS settings = %+v", pdns)
	}
	if other := c.Backends[1].PowerDNS; other.Timeout != 5*time.Second || other.ServerID != "localhost" {
		t.Errorf("PowerDNS defaults = %+v", other)
	}

	zone := c.Zones[0]
	if zone.Name != "example.test." || zone.Backend != "pdns" || !slices.Equal(zone.Keys, []string{"admin."}) {
		t.Errorf("zone = %+v", zone)
	}
	rule := zone.Policy[0]
	if rule.Key != "cert-manager." ||
		!slices.Equal(rule.Names, []string{"_acme-challenge.example.test.", "_acme-challenge.**.example.test."}) ||
		!slices.Equal(rule.Types, []string{"TXT"}) {
		t.Errorf("rule = %+v", rule)
	}
	if !c.Zones[1].AllowUnauthenticated {
		t.Error("open.test. should accept unauthenticated updates")
	}

	for _, want := range []string{
		"keys[1].secret: 28 bytes is shorter than the 32-byte output of hmac-sha256",
		"keys[2].algorithm: RFC 8945 forbids HMAC-MD5",
		"zones[1]: accepts unauthenticated updates",
	} {
		if !slices.ContainsFunc(warnings, func(w string) bool { return strings.Contains(w, want) }) {
			t.Errorf("missing warning %q in %q", want, warnings)
		}
	}
}

func TestParseDefaults(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../test/config/valid/minimal.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, warnings, err := config.Parse(data, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Listen, []string{config.DefaultListen}) {
		t.Errorf("Listen = %q, want the default", c.Listen)
	}
	if c.Keys[0].Algorithm != config.HMACSHA256 {
		t.Errorf("default algorithm = %s", c.Keys[0].Algorithm)
	}
	if c.Zones[0].Backend != "pdns" {
		t.Errorf("default backend = %q", c.Zones[0].Backend)
	}
	if len(warnings) != 0 {
		t.Errorf("unexpected warnings %q", warnings)
	}
}

func TestParseEmpty(t *testing.T) {
	t.Parallel()

	if _, _, err := config.Parse(nil, testOptions()); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("Parse(nil) error = %v, want an empty configuration error", err)
	}
}
