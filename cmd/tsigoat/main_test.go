package main

import (
	"bytes"
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
		"is valid: 3 keys, 2 backends, 2 zones",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("output %q lacks %q", stdout, want)
		}
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
		{[]string{"serve", "--config", "/nonexistent/tsigoat.yaml"}, "error: reading the configuration"},
		{[]string{"serve", "--log-level", "loud"}, "error: unknown log level"},
		{[]string{"serve", "--log-format", "xml"}, "error: unknown log format"},
		{[]string{"serve", "extra"}, "error: unknown command"},
	} {
		code, _, stderr := execute(tt.args...)
		if code != 1 || !strings.Contains(stderr, tt.want) {
			t.Errorf("%v: code %d, stderr %q, want %q", tt.args, code, stderr, tt.want)
		}
	}
}
