package auth

import (
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/config"
)

func TestMatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"www.example.test.", "www.example.test.", true},
		{"www.example.test.", "ftp.example.test.", false},
		{"www.example.test.", "a.www.example.test.", false},
		{"example.test.", "example.test.", true},
		{"*.example.test.", "www.example.test.", true},
		{"*.example.test.", "example.test.", false},
		{"*.example.test.", "a.b.example.test.", false},
		{"**.example.test.", "www.example.test.", true},
		{"**.example.test.", "a.b.c.example.test.", true},
		{"**.example.test.", "example.test.", false},
		{"_acme-challenge.**.example.test.", "_acme-challenge.www.example.test.", true},
		{"_acme-challenge.**.example.test.", "_acme-challenge.a.b.example.test.", true},
		{"_acme-challenge.**.example.test.", "_acme-challenge.example.test.", false},
		{"_acme-challenge.**.example.test.", "www.example.test.", false},
		{"_acme-challenge.**.example.test.", "x._acme-challenge.www.example.test.", false},
		{"*.**.example.test.", "a.example.test.", false},
		{"*.**.example.test.", "a.b.example.test.", true},
		{"**.*.example.test.", "a.b.c.example.test.", true},
		{"a.**.b.**.example.test.", "a.x.b.y.z.example.test.", true},
		{"a.**.b.**.example.test.", "a.b.y.example.test.", false},
		{`a\.b.example.test.`, `a\.b.example.test.`, true},
		{`*.example.test.`, `a\.b.example.test.`, true},
	}
	for _, tt := range tests {
		if got := match(labels(tt.pattern), labels(tt.name)); got != tt.want {
			t.Errorf("match(%q, %q) = %v, want %v", tt.pattern, tt.name, got, tt.want)
		}
	}
}

// naiveMatch is the backtracking definition of match.
func naiveMatch(pattern, name []string) bool {
	if len(pattern) == 0 {
		return len(name) == 0
	}
	switch pattern[0] {
	case "**":
		for i := 1; i <= len(name); i++ {
			if naiveMatch(pattern[1:], name[i:]) {
				return true
			}
		}
		return false
	case "*":
		return len(name) > 0 && naiveMatch(pattern[1:], name[1:])
	default:
		return len(name) > 0 && pattern[0] == name[0] && naiveMatch(pattern[1:], name[1:])
	}
}

func FuzzMatch(f *testing.F) {
	f.Add("_acme-challenge.**.example.test", "_acme-challenge.a.b.example.test")
	f.Add("*.**.*", "a.b.c")
	f.Add("**.**", "a")
	f.Fuzz(func(t *testing.T, pattern, name string) {
		// Short label lists keep the backtracking reference fast.
		p, n := strings.Split(pattern, "."), strings.Split(name, ".")
		if len(p) > 8 || len(n) > 12 {
			return
		}
		if got, want := match(p, n), naiveMatch(p, n); got != want {
			t.Errorf("match(%q, %q) = %v, want %v", p, n, got, want)
		}
	})
}

func TestPolicy(t *testing.T) {
	t.Parallel()

	policy, err := NewPolicy(&config.Zone{
		Name: "example.test.",
		Keys: []string{"admin."},
		Policy: []config.Rule{
			{Key: "acme.", Names: []string{"_acme-challenge.example.test.", "_acme-challenge.**.example.test."}, Types: []string{"TXT"}},
			{Key: "dhcp.", Names: []string{"*.dhcp.example.test."}},
			{Key: "soa.", Names: []string{"example.test."}, Types: []string{"SOA", "NS"}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, identity := range []string{"admin.", "acme.", "dhcp.", "soa."} {
		if !policy.Admits(identity) {
			t.Errorf("Admits(%q) = false", identity)
		}
	}
	for _, identity := range []string{Unauthenticated, "other."} {
		if policy.Admits(identity) {
			t.Errorf("Admits(%q) = true", identity)
		}
	}

	tests := []struct {
		identity string
		name     string
		rrtype   uint16
		want     bool
	}{
		{"admin.", "www.example.test.", dns.TypeA, true},
		{"admin.", "example.test.", dns.TypeNS, true},
		{"admin.", "example.test.", dns.TypeANY, true},
		{"admin.", "example.test.", dns.TypeSOA, false},
		{"acme.", "_acme-challenge.www.example.test.", dns.TypeTXT, true},
		{"acme.", "_acme-challenge.example.test.", dns.TypeTXT, true},
		{"acme.", "_acme-challenge.www.example.test.", dns.TypeA, false},
		{"acme.", "_acme-challenge.www.example.test.", dns.TypeANY, false},
		{"acme.", "www.example.test.", dns.TypeTXT, false},
		{"dhcp.", "host.dhcp.example.test.", dns.TypeA, true},
		{"dhcp.", "host.dhcp.example.test.", dns.TypeANY, true},
		{"dhcp.", "host.dhcp.example.test.", dns.TypeSOA, false},
		{"dhcp.", "dhcp.example.test.", dns.TypeA, false},
		{"soa.", "example.test.", dns.TypeSOA, true},
		{"soa.", "example.test.", dns.TypeNS, true},
		{"soa.", "example.test.", dns.TypeTXT, false},
		{"other.", "www.example.test.", dns.TypeA, false},
		{Unauthenticated, "www.example.test.", dns.TypeA, false},
	}
	for _, tt := range tests {
		if got := policy.AllowsUpdate(tt.identity, tt.name, tt.rrtype); got != tt.want {
			t.Errorf("AllowsUpdate(%q, %q, %s) = %v, want %v",
				tt.identity, tt.name, dns.TypeToString[tt.rrtype], got, tt.want)
		}
	}

	names := []struct {
		identity string
		name     string
		want     bool
	}{
		{"admin.", "anything.example.test.", true},
		{"acme.", "_acme-challenge.www.example.test.", true},
		{"acme.", "www.example.test.", false},
		{"soa.", "example.test.", true},
		{Unauthenticated, "www.example.test.", false},
	}
	for _, tt := range names {
		if got := policy.AllowsName(tt.identity, tt.name); got != tt.want {
			t.Errorf("AllowsName(%q, %q) = %v, want %v", tt.identity, tt.name, got, tt.want)
		}
	}
}

func TestPolicyUnauthenticated(t *testing.T) {
	t.Parallel()

	policy, err := NewPolicy(&config.Zone{Name: "open.test.", AllowUnauthenticated: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range []string{Unauthenticated, "any.key."} {
		if !policy.Admits(identity) || !policy.AllowsName(identity, "www.open.test.") {
			t.Errorf("%q is not admitted to an open zone", identity)
		}
		if !policy.AllowsUpdate(identity, "www.open.test.", dns.TypeA) {
			t.Errorf("AllowsUpdate(%q, A) = false in an open zone", identity)
		}
		if policy.AllowsUpdate(identity, "open.test.", dns.TypeSOA) {
			t.Errorf("AllowsUpdate(%q, SOA) = true in an open zone", identity)
		}
	}
}

func TestNewPolicyUnknownType(t *testing.T) {
	t.Parallel()

	_, err := NewPolicy(&config.Zone{
		Name:   "example.test.",
		Policy: []config.Rule{{Key: "k.", Names: []string{"example.test."}, Types: []string{"NOPE"}}},
	})
	if err == nil {
		t.Error("NewPolicy() accepted an unknown type")
	}
}
