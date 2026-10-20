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
		"TSIGOAT_TEST_SECRET":  "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0LCB0aGlydHktdHdvIQ==", // gitleaks:allow (fixture)
		"TSIGOAT_TEST_API_KEY": "test-api-key",
		"TSIGOAT_TEST_BLANK":   " \n",
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
	if c.AdminListen != "[::]:9153" {
		t.Errorf("AdminListen = %q", c.AdminListen)
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
	relay := c.Backends[2].RFC2136
	if c.Backends[2].PowerDNS != nil || relay.Server != "ns1.example.test:53" || relay.Timeout != 3*time.Second ||
		relay.Key.Name != "tsigoat." || relay.Key.Algorithm != config.HMACSHA1 ||
		string(relay.Key.Secret) != "this is a test secret, thirty-two!" {
		t.Errorf("RFC 2136 settings = %+v", relay)
	}

	hook := c.Backends[3].Webhook
	if hook.URL != "https://hooks.example.test/tsigoat" || hook.Timeout != 2*time.Second || !hook.FollowRedirects ||
		!hook.InsecureSkipVerify || hook.SignatureSecret != "test-api-key" ||
		hook.Username != "tsigoat" || hook.Password != "dGhpcyBpcyBub3QgYSBzZWNyZXQgYXQgYWxsIQ==" || hook.BearerToken != "" ||
		!slices.Equal(hook.Headers, []config.Header{{Name: "X-Tenant", Value: "dns"}, {Name: "X-Api-Key", Value: "test-api-key"}}) {
		t.Errorf("webhook settings = %+v", hook)
	}

	zone := c.Zones[0]
	if zone.Name != "example.test." || zone.Backend != "pdns" || !slices.Equal(zone.Keys, []string{"admin."}) {
		t.Errorf("zone = %+v", zone)
	}
	acme := zone.Policy[0]
	if acme.Key != "cert-manager." ||
		!slices.Equal(acme.Names, []string{"_acme-challenge.example.test.", "_acme-challenge.**.example.test."}) ||
		!slices.Equal(acme.Types, []string{"TXT"}) ||
		acme.Content != config.ACMEContent || acme.MaxTTL != 300 || acme.MaxRecords != 10 {
		t.Errorf("acme rule = %+v", acme)
	}
	if dhcp := zone.Policy[1]; dhcp.MaxTTL != 3600 || dhcp.MaxRecords != 4 || dhcp.Content != config.AnyContent {
		t.Errorf("rule with bounds = %+v", dhcp)
	}
	if content := zone.Policy[2]; !slices.Equal(content.Types, []string{"TXT"}) || content.Content != config.ACMEContent ||
		content.MaxTTL != 0 || content.MaxRecords != 0 {
		t.Errorf("rule with ACME content = %+v", content)
	}
	if !c.Zones[1].AllowUnauthenticated {
		t.Error("open.test. should accept unauthenticated updates")
	}

	for _, want := range []string{
		"keys[1].secret: 28 bytes is shorter than the 32-byte output of hmac-sha256",
		"keys[2].algorithm: RFC 8945 forbids HMAC-MD5",
		"backends[2].rfc2136.key.algorithm: RFC 8945 recommends against HMAC-SHA1: switch the name server",
		"backends[3].webhook.insecureSkipVerify: accepts any certificate: someone in the middle may read the requests, " +
			"steal the credentials",
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

// TestExamples keeps the example configurations valid. Their files and
// variables do not exist here: every one reads as a valid secret. The test of
// the chart validates the configurations of examples/helm.
func TestExamples(t *testing.T) {
	t.Parallel()

	const secret = "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0LCB0aGlydHktdHdvIQ==" // gitleaks:allow (fixture)
	options := config.Options{
		LookupEnv: func(string) (string, bool) { return secret, true },
		ReadFile:  func(string) ([]byte, error) { return []byte(secret), nil },
	}
	for _, path := range fixtures(t, "../../examples/*.yaml") {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := config.Parse(data, options); err != nil {
			t.Errorf("%s: %v", path, err)
		}
	}
}

func TestParseProviders(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile("../../test/config/valid/providers.yaml")
	if err != nil {
		t.Fatal(err)
	}
	c, _, err := config.Parse(data, testOptions())
	if err != nil {
		t.Fatal(err)
	}
	if cf := c.Backends[0].Cloudflare; cf.APIToken != "test-api-key" || cf.Timeout != 10*time.Second ||
		len(cf.ZoneIDs) != 1 || cf.ZoneIDs["cloudflare.test."] != "023e105f4ecef8ad9ca31a8372d0c353" {
		t.Errorf("Cloudflare settings = %+v", cf)
	}
	if o := c.Backends[1].OVH; o.Endpoint != "https://eu.api.ovh.com/1.0" || o.ApplicationKey != "7kbG7Bk7S9Nt7ZSV" ||
		o.ApplicationSecret != "dGhpcyBpcyBub3QgYSBzZWNyZXQgYXQgYWxsIQ==" || o.ConsumerKey != "test-api-key" ||
		o.ClientID != "" || o.Timeout != 5*time.Second {
		t.Errorf("OVH settings = %+v", o)
	}
	if o := c.Backends[2].OVH; o.Endpoint != "https://ca.api.ovh.com/1.0" || o.ApplicationKey != "" ||
		o.ClientID != "EU.a1b2c3d4e5f6" || o.ClientSecret != "test-api-key" {
		t.Errorf("OVH settings with a service account = %+v", o)
	}
	if o := c.Backends[3].OVH; o.Endpoint != "https://eu.api.ovh.com/1.0" {
		t.Errorf("OVH endpoint given as a URL = %q", o.Endpoint)
	}
	if s := c.Backends[4].Scaleway; s.SecretKey != "test-api-key" || s.Timeout != 5*time.Second {
		t.Errorf("Scaleway settings = %+v", s)
	}
}
