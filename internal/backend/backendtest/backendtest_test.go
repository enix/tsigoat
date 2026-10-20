package backendtest

import (
	"strings"
	"testing"

	"github.com/enix/tsigoat/internal/backend"
)

// TestCompare checks that the suite sees the faults of a backend: a lost or
// extra value, an RRset left behind, a TTL ignored, a duplicate.
func TestCompare(t *testing.T) {
	t.Parallel()
	const name = "www.example.test."
	two := parse(t, name, ttl, `TXT "a"`, `TXT "b"`)
	for _, c := range []struct {
		label    string
		got      []backend.RRset
		want     []backend.RRset
		mismatch string
	}{
		{label: "same", got: two, want: two},
		{label: "other order", got: parse(t, name, ttl, `TXT "b"`, `TXT "a"`), want: two},
		{label: "lost value", got: parse(t, name, ttl, `TXT "b"`), want: two, mismatch: "other records"},
		{label: "extra value", got: parse(t, name, ttl, `TXT "a"`, `TXT "b"`, `TXT "c"`), want: two, mismatch: "other records"},
		{label: "duplicate", got: parse(t, name, ttl, `TXT "a"`, `TXT "a"`), want: two, mismatch: "other records"},
		{label: "ignored TTL", got: two, want: parse(t, name, 2*ttl, `TXT "a"`, `TXT "b"`), mismatch: "TTL 300 instead of 600"},
		{label: "RRset left", got: append(parse(t, name, ttl, "A 192.0.2.1"), two...), want: two, mismatch: "2 RRsets instead of 1"},
		{label: "RRset missing", got: nil, want: two, mismatch: "0 RRsets instead of 1"},
		{label: "other type", got: parse(t, name, ttl, "A 192.0.2.1"), want: two, mismatch: "missing TXT"},
		{label: "other name", got: parse(t, "other.example.test.", ttl, `TXT "a"`, `TXT "b"`), want: two, mismatch: "name other.example.test."},
		{label: "case of RDATA names", got: parse(t, name, ttl, "MX 10 MAIL.example.net."), want: parse(t, name, ttl, "MX 10 mail.example.net.")},
		{label: "case of hexadecimal", got: parse(t, name, ttl, "SSHFP 4 2 AB12"), want: parse(t, name, ttl, "SSHFP 4 2 ab12")},
		{label: "forms of IPv6", got: parse(t, name, ttl, "AAAA 2001:db8:0:0::1"), want: parse(t, name, ttl, "AAAA 2001:db8::1")},
		{label: "escapes of TXT", got: parse(t, name, ttl, `TXT "caf\195\169"`), want: parse(t, name, ttl, "TXT \"caf\xc3\xa9\"")},
	} {
		diff := compare(c.got, c.want)
		switch {
		case c.mismatch == "" && diff != "":
			t.Errorf("%s: compare() = %q, want no difference", c.label, diff)
		case c.mismatch != "" && !strings.Contains(diff, c.mismatch):
			t.Errorf("%s: compare() = %q, want %q", c.label, diff, c.mismatch)
		}
	}
}

// TestCases checks that the records of the cases parse, and that their names
// are distinct.
func TestCases(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for _, name := range usedNames() {
		if seen[name] {
			t.Errorf("name %s is used twice", name)
		}
		seen[name] = true
	}
	for _, c := range append(txtCases(), typeCases()...) {
		if sets := parse(t, "www.example.test.", ttl, c.records...); len(sets) == 0 {
			t.Errorf("case %s has no record", c.label)
		}
	}
}
