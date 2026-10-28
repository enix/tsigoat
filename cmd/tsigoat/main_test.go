package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func execute(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func TestVersion(t *testing.T) {
	t.Parallel()

	code, stdout, _ := execute("version", "--short")
	if code != 0 || strings.TrimSpace(stdout) == "" || strings.Contains(stdout, "\n\n") {
		t.Errorf("version --short: code %d, output %q", code, stdout)
	}
	code, stdout, _ = execute("version")
	if code != 0 || !strings.Contains(stdout, "Version:") || !strings.Contains(stdout, "Platform:") {
		t.Errorf("version: code %d, output %q", code, stdout)
	}
}

func TestCheckConfig(t *testing.T) {
	t.Setenv("TSIGOAT_TEST_SECRET", "dGhpcyBpcyBhIHRlc3Qgc2VjcmV0LCB0aGlydHktdHdvIQ==") // gitleaks:allow (fixture)
	t.Setenv("TSIGOAT_TEST_API_KEY", "test-api-key")

	code, stdout, stderr := execute("check-config", "--config", "../../test/config/valid/full.yaml")
	if code != 0 {
		t.Fatalf("valid configuration: code %d, stderr %q", code, stderr)
	}
	for _, want := range []string{
		"warning: keys[2].algorithm: RFC 8945 forbids HMAC-MD5",
		"warning: zones[1]: accepts unauthenticated updates",
		"is valid: 3 keys, 4 backends, 4 zones",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output %q lacks %q", stdout, want)
		}
	}

	// The backends of the fixture do not exist.
	code, stdout, _ = execute("check-config", "--config", "../../test/config/valid/full.yaml", "--backends")
	if code != 1 || !strings.Contains(stdout, "failure: zone example.test. on backend pdns") {
		t.Errorf("--backends: code %d, output %q", code, stdout)
	}

	code, _, stderr = execute("check-config", "--config", "../../test/config/invalid/key-duplicate.yaml")
	if code != 1 || !strings.Contains(stderr, "error: keys[1].name: duplicate key") {
		t.Errorf("invalid configuration: code %d, stderr %q", code, stderr)
	}
}

func TestServeErrors(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		args []string
		want string
	}{
		{[]string{"serve", "--log-level", "loud"}, "error: unknown log level"},
		{[]string{"serve", "--log-format", "xml"}, "error: unknown log format"},
		{[]string{"serve", "--shutdown-delay", "-1s"}, "error: --shutdown-delay is -1s: a delay cannot be negative"},
		{[]string{"serve", "extra"}, "error: unknown command"},
	} {
		code, _, stderr := execute(tt.args...)
		if code != 1 || !strings.Contains(stderr, tt.want) {
			t.Errorf("%v: code %d, stderr %q, want %q", tt.args, code, stderr, tt.want)
		}
	}
}

// TestServeLogsItsStop checks that serve tells in its log, in its format, why
// it stops: a configuration that does not load gives one record, with its
// errors as a list, and nothing out of the log.
func TestServeLogsItsStop(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, []byte("A-REMPLACER\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(config, []byte(`keys:
  - name: k1.
    secretFile: `+secret+`
  - name: k2.
    secretFile: `+secret+`
backends:
  - name: pdns
    type: powerdns
    powerdns:
      url: http://127.0.0.1:1
      apiKey: unused
zones:
  - name: example.test.
    keys: [k1., k2.]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := execute("serve", "--config", config, "--log-format", "json", "--auto-gomemlimit=false")
	if code != 1 {
		t.Errorf("serve exited with %d, want 1", code)
	}
	var last struct {
		Level  string   `json:"level"`
		Msg    string   `json:"msg"`
		Error  string   `json:"error"`
		Path   string   `json:"path"`
		Errors []string `json:"errors"`
	}
	for line := range strings.Lines(strings.TrimSpace(stderr)) {
		if err := json.Unmarshal([]byte(line), &last); err != nil {
			t.Fatalf("a line of the error output is not a JSON record: %q", line)
		}
	}
	want := []string{
		"keys[0].secretFile: not valid base64, in " + secret + ": illegal base64 data at input byte 1",
		"keys[1].secretFile: not valid base64, in " + secret + ": illegal base64 data at input byte 1",
	}
	if last.Level != "ERROR" || last.Msg != "stopped" || last.Error != "invalid configuration" ||
		last.Path != config || !slices.Equal(last.Errors, want) {
		t.Errorf("last record %+v, want the stop with the errors %q", last, want)
	}
}
