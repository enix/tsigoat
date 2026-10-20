package hosted_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/hosted"
)

func rr(t *testing.T, text string) dns.RR {
	t.Helper()
	parsed, err := dns.NewRR(text)
	if err != nil || parsed == nil {
		t.Fatalf("parsing %q: %v", text, err)
	}
	return parsed
}

func records(t *testing.T, lines ...string) []hosted.Record {
	t.Helper()
	held := make([]hosted.Record, 0, len(lines))
	for i, line := range lines {
		held = append(held, hosted.Record{ID: string(rune('a' + i)), RR: rr(t, line)})
	}
	return held
}

func TestRRsets(t *testing.T) {
	t.Parallel()
	sets := hosted.RRsets(records(t,
		`www.example.test. 300 IN TXT "a"`,
		"www.example.test. 600 IN A 192.0.2.1",
		`www.example.test. 120 IN TXT "b"`,
	))
	if len(sets) != 2 || sets[0].Type != dns.TypeA || sets[1].Type != dns.TypeTXT {
		t.Fatalf("RRsets() = %v, want the A then the TXT RRset", sets)
	}
	if sets[1].TTL != 120 || len(sets[1].Records) != 2 {
		t.Errorf("TXT RRset = %v, want two records with the lowest TTL", sets[1])
	}
	for _, record := range sets[1].Records {
		if record.Header().Ttl != 120 {
			t.Errorf("record %s keeps its own TTL", record)
		}
	}
}

// describe lists steps as text, such as "delete a", "create www... TXT b",
// "retime b 600".
func describe(steps *hosted.Steps) string {
	lines := make([]string, 0, len(steps.Delete)+len(steps.Create)+len(steps.Retime))
	for _, r := range steps.Delete {
		lines = append(lines, "delete "+r.ID)
	}
	for _, created := range steps.Create {
		lines = append(lines, "create "+created.String())
	}
	for _, r := range steps.Retime {
		lines = append(lines, "retime "+r.ID+" "+r.RR.String())
	}
	slices.Sort(lines)
	return strings.Join(lines, "\n")
}

func TestDiff(t *testing.T) {
	t.Parallel()
	const name = "www.example.test."
	current := records(t,
		name+` 300 IN TXT "a"`,
		name+` 300 IN TXT "b"`,
		name+` 300 IN TXT "b"`,
	)
	replace := func(ttl uint32, values ...string) *backend.Change {
		set := backend.RRset{Name: name, Type: dns.TypeTXT, TTL: ttl}
		for _, value := range values {
			set.Records = append(set.Records, rr(t, name+" 1 IN TXT "+value))
		}
		return &backend.Change{Op: backend.Replace, RRset: set}
	}
	for _, c := range []struct {
		label  string
		change *backend.Change
		want   []string
	}{
		{label: "same", change: replace(300, `"a"`, `"b"`), want: []string{"delete c"}},
		{label: "swap", change: replace(300, `"b"`, `"c"`), want: []string{
			"create " + name + "\t300\tIN\tTXT\t\"c\"", "delete a", "delete c",
		}},
		{label: "ttl", change: replace(600, `"a"`, `"b"`), want: []string{
			"delete c", "retime a " + name + "\t600\tIN\tTXT\t\"a\"", "retime b " + name + "\t600\tIN\tTXT\t\"b\"",
		}},
		{label: "both duplicates", change: replace(300, `"a"`, `"b"`, `"b"`), want: nil},
		{label: "delete", change: &backend.Change{Op: backend.Delete, RRset: backend.RRset{Name: name, Type: dns.TypeTXT}}, want: []string{
			"delete a", "delete b", "delete c",
		}},
	} {
		steps := hosted.Diff(current, c.change)
		if got, want := describe(&steps), strings.Join(c.want, "\n"); got != want {
			t.Errorf("%s: Diff() =\n%s\nwant\n%s", c.label, got, want)
		}
		if steps.Empty() != (len(c.want) == 0) {
			t.Errorf("%s: Empty() = %t", c.label, steps.Empty())
		}
	}
	if steps := hosted.Diff(nil, replace(60, `"new"`)); len(steps.Create) != 1 || steps.Create[0].Header().Ttl != 60 {
		t.Errorf("Diff() of a new RRset = %s, want the record created with the TTL of the RRset", describe(&steps))
	}
}

func TestEscapes(t *testing.T) {
	t.Parallel()
	for escaped, raw := range map[string]string{
		`plain`:            "plain",
		`say \"hi\"`:       `say "hi"`,
		`back\\slash`:      `back\slash`,
		`caf\195\169`:      "caf\xc3\xa9",
		`h2\;foo`:          "h2;foo",
		`!^.*$!sip:\\1@x!`: `!^.*$!sip:\1@x!`,
		`\0010`:            "\x010",
		`end\\`:            `end\`,
	} {
		got, err := hosted.Unescape(escaped)
		if err != nil || got != raw {
			t.Errorf("Unescape(%q) = %q, %v, want %q", escaped, got, err, raw)
		}
		if back, _ := hosted.Unescape(hosted.Escape(raw)); back != raw {
			t.Errorf("Unescape(Escape(%q)) = %q", raw, back)
		}
	}
	for _, invalid := range []string{`trailing\`, `\256`} {
		if _, err := hosted.Unescape(invalid); err == nil {
			t.Errorf("Unescape(%q) succeeded", invalid)
		}
	}
	for s, printable := range map[string]bool{
		`plain`: true, `say \"hi\"`: true, `\\1`: true, `\1@`: true, `caf\195\169`: false, `\000`: false,
	} {
		if got := hosted.Printable(s); got != printable {
			t.Errorf("Printable(%q) = %t, want %t", s, got, printable)
		}
	}
}
