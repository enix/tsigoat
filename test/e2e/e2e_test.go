//go:build e2e

// Package e2e runs the scenarios of test/scenario against tsigoat placed in
// front of a real PowerDNS server.
//
// `task test:e2e` runs it inside Dagger. To run it against the development
// backend of `task dev` instead:
//
//	TSIGOAT_E2E_PDNS_URL=http://127.0.0.1:8081 \
//	TSIGOAT_E2E_PDNS_API_KEY=ZGV2LWFwaS1rZXk= \
//	go test -tags e2e ./test/e2e/
package e2e

import (
	"context"
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // HMAC-MD5 is a TSIG algorithm under test
	"crypto/sha1" //nolint:gosec // HMAC-SHA1 is a TSIG algorithm under test
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/test/scenario"
)

// parentDomain holds the zone of every scenario.
const parentDomain = "e2e.test."

func TestScenarios(t *testing.T) {
	t.Parallel()

	env := newEnvironment(t)
	scenarios, err := scenario.All()
	if err != nil {
		t.Fatal(err)
	}

	backend := newPowerDNS(env.pdnsURL, env.pdnsAPIKey)
	server := startTsigoat(t, env, scenarios)

	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			runScenario(t, backend, server, &s)
		})
	}
}

func runScenario(t *testing.T, backend *powerDNS, server *tsigoat, s *scenario.Scenario) {
	t.Helper()
	ctx := t.Context()
	zone := s.ZoneName(parentDomain)

	if err := backend.resetZone(ctx, zone); err != nil {
		t.Fatalf("resetting zone %s: %v", zone, err)
	}
	records, err := scenario.ParseRecords(s.Zone.Records, zone)
	if err != nil {
		t.Fatal(err)
	}
	err = backend.addRecords(ctx, zone, records)
	if err != nil {
		t.Fatalf("adding the records of the zone: %v", err)
	}
	initial, err := backend.records(ctx, zone)
	if err != nil {
		t.Fatalf("reading the zone: %v", err)
	}

	responses, err := send(ctx, server.addr, s, zone)
	if err != nil {
		t.Fatal(err)
	}

	final, err := backend.records(ctx, zone)
	if err != nil {
		t.Fatalf("reading the zone: %v", err)
	}

	problems := checkResponses(s, responses)
	problems = append(problems, checkRecords(s, zone, initial, final)...)
	verdict(t, s, problems)
}

// verdict reports the problems of a scenario. A scenario with a known defect
// must fail: its failure is reported as skipped, and a pass fails the test so
// that the marker goes away with the fix.
func verdict(t *testing.T, s *scenario.Scenario, problems []string) {
	t.Helper()
	switch {
	case s.KnownDefect != "" && len(problems) > 0:
		t.Skipf("known defect %s:\n%s", s.KnownDefect, strings.Join(problems, "\n"))
	case s.KnownDefect != "":
		t.Errorf("the scenario passes despite known defect %s: remove its knownDefect marker", s.KnownDefect)
	case len(problems) > 0:
		t.Errorf("%s\n%s", s.Description, strings.Join(problems, "\n"))
	}
}

type response struct {
	msg *dns.Msg
	err error
}

// send sends the requests of the scenario, in order or all at once.
func send(ctx context.Context, addr string, s *scenario.Scenario, zone string) ([]response, error) {
	type exchangeJob struct {
		request *scenario.Request
		msg     *dns.Msg
	}
	var jobs []exchangeJob
	for i := range s.Requests {
		messages, err := s.Requests[i].Messages(zone)
		if err != nil {
			return nil, fmt.Errorf("request %d: %w", i, err)
		}
		for _, m := range messages {
			jobs = append(jobs, exchangeJob{request: &s.Requests[i], msg: m})
		}
	}

	responses := make([]response, len(jobs))
	if !s.Parallel {
		for i, job := range jobs {
			responses[i] = exchange(ctx, addr, job.request, job.msg)
		}
		return responses, nil
	}
	var wg sync.WaitGroup
	for i, job := range jobs {
		wg.Go(func() {
			responses[i] = exchange(ctx, addr, job.request, job.msg)
		})
	}
	wg.Wait()
	return responses, nil
}

func exchange(ctx context.Context, addr string, r *scenario.Request, m *dns.Msg) response {
	client := &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	if key, algorithm, ok := r.Signer(); ok {
		secret := key.Secret()
		if r.BadSignature {
			secret = base64.StdEncoding.EncodeToString([]byte("not the secret of the key"))
		}
		decoded, err := base64.StdEncoding.DecodeString(secret)
		if err != nil {
			return response{err: fmt.Errorf("decoding the secret of key %s: %w", key.ID, err)}
		}
		client.TsigProvider = hmacProvider(decoded)
		m.SetTsig(key.Name, algorithm, 300, time.Now().Unix()+r.TimeShift)
	}
	in, _, err := client.ExchangeContext(ctx, m, addr)
	return response{msg: in, err: err}
}

// hmacProvider signs and verifies TSIG with a single secret. Unlike the
// provider of miekg/dns, it supports HMAC-MD5, which tsigoat accepts as a
// legacy opt-in.
type hmacProvider []byte

func (p hmacProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	var newHash func() hash.Hash
	switch dns.CanonicalName(t.Algorithm) {
	case dns.HmacMD5:
		newHash = md5.New
	case dns.HmacSHA1:
		newHash = sha1.New
	case dns.HmacSHA224:
		newHash = sha256.New224
	case dns.HmacSHA256:
		newHash = sha256.New
	case dns.HmacSHA384:
		newHash = sha512.New384
	case dns.HmacSHA512:
		newHash = sha512.New
	default:
		return nil, dns.ErrKeyAlg
	}
	mac := hmac.New(newHash, p)
	mac.Write(msg)
	return mac.Sum(nil), nil
}

func (p hmacProvider) Verify(msg []byte, t *dns.TSIG) error {
	expected, err := p.Generate(msg, t)
	if err != nil {
		return err
	}
	received, err := hex.DecodeString(t.MAC)
	if err != nil {
		return fmt.Errorf("decoding the MAC: %w", err)
	}
	if !hmac.Equal(expected, received) {
		return dns.ErrSig
	}
	return nil
}

func checkResponses(s *scenario.Scenario, responses []response) []string {
	var problems []string
	want := s.ExpectedRcode()
	for i, r := range responses {
		prefix := fmt.Sprintf("response %d", i)
		if r.msg == nil {
			problems = append(problems, fmt.Sprintf("%s: none received: %v", prefix, r.err))
			continue
		}
		if got := dns.RcodeToString[r.msg.Rcode]; got != want {
			problems = append(problems, fmt.Sprintf("%s: rcode %s, want %s", prefix, got, want))
		}
		tsig := r.msg.IsTsig()
		if s.Expect.TSIGError != "" {
			switch {
			case tsig == nil:
				problems = append(problems, fmt.Sprintf("%s: no TSIG record, want TSIG error %s", prefix, s.Expect.TSIGError))
			case dns.RcodeToString[int(tsig.Error)] != s.Expect.TSIGError:
				problems = append(problems, fmt.Sprintf("%s: TSIG error %s, want %s",
					prefix, dns.RcodeToString[int(tsig.Error)], s.Expect.TSIGError))
			}
		}
		if s.Expect.SignedResponse {
			switch {
			case tsig == nil:
				problems = append(problems, prefix+": not signed")
			case r.err != nil:
				problems = append(problems, fmt.Sprintf("%s: invalid signature: %v", prefix, r.err))
			}
		}
	}
	return problems
}

// checkRecords compares the zone after the requests with the expected
// records, or with the zone before the requests when the scenario expects no
// change.
func checkRecords(s *scenario.Scenario, zone string, initial, final []string) []string {
	want := initial
	if s.Expect.Records != nil {
		expected, err := scenario.ParseRecords(*s.Expect.Records, zone)
		if err != nil {
			return []string{err.Error()}
		}
		want = make([]string, 0, len(expected)+1)
		listsApexNS := false
		for _, rr := range expected {
			if rr.Header().Rrtype == dns.TypeNS && dns.CanonicalName(rr.Header().Name) == zone {
				listsApexNS = true
			}
			want = append(want, normalize(rr))
		}
		if !listsApexNS {
			want = append(want, apexNS(initial, zone)...)
		}
		sort.Strings(want)
	}
	return diffRecords(want, final)
}

// apexNS returns the NS records of the apex among normalised records.
func apexNS(records []string, zone string) []string {
	var ns []string
	for _, r := range records {
		if strings.HasPrefix(r, zone+" ") && strings.Contains(r, " IN NS ") {
			ns = append(ns, r)
		}
	}
	return ns
}

func diffRecords(want, got []string) []string {
	remaining := map[string]int{}
	for _, r := range got {
		remaining[r]++
	}
	var problems []string
	for _, r := range want {
		if remaining[r] > 0 {
			remaining[r]--
			continue
		}
		problems = append(problems, "missing record: "+r)
	}
	for _, r := range got {
		if remaining[r] > 0 {
			remaining[r]--
			problems = append(problems, "unexpected record: "+r)
		}
	}
	return problems
}
