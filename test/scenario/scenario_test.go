package scenario_test

import (
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/test/scenario"
)

func TestAllScenariosLoad(t *testing.T) {
	t.Parallel()

	scenarios, err := scenario.All()
	if err != nil {
		t.Fatal(err)
	}
	if len(scenarios) == 0 {
		t.Fatal("no scenario found")
	}
	for _, s := range scenarios {
		if _, ok := dns.IsDomainName(s.ZoneName("e2e.test.")); !ok {
			t.Errorf("scenario %s: invalid zone name %q", s.Name, s.ZoneName("e2e.test."))
		}
	}
}

func TestZoneName(t *testing.T) {
	t.Parallel()

	s := scenario.Scenario{Name: "prerequisites/nxdomain-holds"}
	if got, want := s.ZoneName("e2e.test"), "nxdomain-holds.prerequisites.e2e.test."; got != want {
		t.Errorf("ZoneName() = %q, want %q", got, want)
	}
}

func TestRequestMessages(t *testing.T) {
	t.Parallel()

	const zone = "example.test."
	tests := []struct {
		name    string
		request scenario.Request
		want    []string
		wantErr bool
	}{
		{
			name: "prerequisites",
			request: scenario.Request{Prerequisites: []string{
				"nxdomain new",
				"yxdomain @",
				"nxrrset www A",
				"yxrrset www AAAA",
				"yxrrset www A 192.0.2.1",
			}},
			// miekg/dns prints class ANY (255) as CLASS255.
			want: []string{
				"new.example.test.\t0\tNONE\tANY\t",
				"example.test.\t0\tCLASS255\tANY\t",
				"www.example.test.\t0\tNONE\tA\t",
				"www.example.test.\t0\tCLASS255\tAAAA\t",
				"www.example.test.\t0\tIN\tA\t192.0.2.1",
			},
		},
		{
			name: "updates",
			request: scenario.Request{Updates: []string{
				`add txt 60 IN TXT "hello world"`,
				"delete gone",
				"delete www A",
				"delete www A 192.0.2.1",
				"rawheader new 300 ANY A",
			}},
			want: []string{
				"txt.example.test.\t60\tIN\tTXT\t\"hello world\"",
				"gone.example.test.\t0\tCLASS255\tANY\t",
				"www.example.test.\t0\tCLASS255\tA\t",
				"www.example.test.\t0\tNONE\tA\t192.0.2.1",
				"new.example.test.\t300\tCLASS255\tA\t",
			},
		},
		{
			name:    "unknown verb",
			request: scenario.Request{Updates: []string{"replace www 60 IN A 192.0.2.1"}},
			wantErr: true,
		},
		{
			name:    "nxrrset with rdata",
			request: scenario.Request{Prerequisites: []string{"nxrrset www A 192.0.2.1"}},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			messages, err := tt.request.Messages(zone)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Messages() succeeded, want an error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			m := messages[0]
			got := make([]string, 0, len(m.Answer)+len(m.Ns))
			for _, rr := range append(m.Answer, m.Ns...) {
				got = append(got, rr.String())
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %d records, want %d: %q", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("record %d = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestRequestRepeatAndShape(t *testing.T) {
	t.Parallel()

	zeroEntries := 0
	request := scenario.Request{
		Repeat:         3,
		ZoneCount:      &zeroEntries,
		UpperCaseNames: true,
		Updates:        []string{`add acme 60 IN TXT "token-{i}"`},
	}
	messages, err := request.Messages("example.test.")
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 3 {
		t.Fatalf("got %d messages, want 3", len(messages))
	}
	for i, m := range messages {
		if len(m.Question) != 0 {
			t.Errorf("message %d: %d zone entries, want 0", i, len(m.Question))
		}
		txt, ok := m.Ns[0].(*dns.TXT)
		if !ok {
			t.Fatalf("message %d: update is %T, want *dns.TXT", i, m.Ns[0])
		}
		if want := []string{"token-" + string(rune('0'+i))}; txt.Txt[0] != want[0] {
			t.Errorf("message %d: TXT %q, want %q", i, txt.Txt, want)
		}
		if txt.Hdr.Name != "ACME.EXAMPLE.TEST." {
			t.Errorf("message %d: owner %q, want it in upper case", i, txt.Hdr.Name)
		}
	}
}
