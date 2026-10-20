package scenario

import (
	"context"
	"crypto/hmac"
	"crypto/md5"  //nolint:gosec // tsigoat supports HMAC-MD5 as a legacy opt-in
	"crypto/sha1" //nolint:gosec // tsigoat supports HMAC-SHA1 as a legacy opt-in
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Target is a tsigoat server in front of a backend that the runner can
// prepare and read.
type Target interface {
	// Addr is the address of tsigoat, for both UDP and TCP.
	Addr() string
	// ResetZone creates the zone afresh, with an SOA record, one apex NS
	// record and the given records.
	ResetZone(ctx context.Context, zone string, records []dns.RR) error
	// Records returns the records of the zone, but its SOA.
	Records(ctx context.Context, zone string) ([]dns.RR, error)
}

// Run runs a scenario against the target, in the zone named after the
// scenario under parent, and reports through t.
//
// A scenario with a known defect must fail: its failure is reported as
// skipped, and a pass fails the test so that the marker goes away with the
// fix.
func Run(t *testing.T, target Target, s *Scenario, parent string) {
	t.Helper()
	ctx := t.Context()
	zone := s.ZoneName(parent)

	records, err := ParseRecords(s.Zone.Records, zone)
	if err != nil {
		t.Fatal(err)
	}
	if resetErr := target.ResetZone(ctx, zone, records); resetErr != nil {
		t.Fatalf("resetting zone %s: %v", zone, resetErr)
	}
	initial, err := normalizedRecords(ctx, target, zone)
	if err != nil {
		t.Fatalf("reading zone %s: %v", zone, err)
	}

	responses, err := send(ctx, target.Addr(), s, zone)
	if err != nil {
		t.Fatal(err)
	}

	final, err := normalizedRecords(ctx, target, zone)
	if err != nil {
		t.Fatalf("reading zone %s: %v", zone, err)
	}

	problems := checkResponses(s, zone, responses)
	problems = append(problems, checkRecords(s, zone, initial, final)...)
	verdict(t, s, problems)
}

func verdict(t *testing.T, s *Scenario, problems []string) {
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

func normalizedRecords(ctx context.Context, target Target, zone string) ([]string, error) {
	records, err := target.Records(ctx, zone)
	if err != nil {
		return nil, err
	}
	normalized := make([]string, 0, len(records))
	for _, rr := range records {
		normalized = append(normalized, Normalize(rr))
	}
	slices.Sort(normalized)
	return normalized, nil
}

// Normalize returns the canonical text of a record, so that records read from
// a backend and records written in a scenario compare equal: the record goes
// through its wire format, which erases the textual variations of its RDATA,
// such as the case of hexadecimal strings or the escapes of TXT strings.
func Normalize(rr dns.RR) string {
	buf := make([]byte, dns.Len(rr)+1)
	if n, err := dns.PackRR(rr, buf, 0, nil, false); err == nil {
		if decoded, _, err := dns.UnpackRR(buf[:n], 0); err == nil {
			rr = decoded
		}
	}
	rr = dns.Copy(rr)
	rr.Header().Name = dns.CanonicalName(rr.Header().Name)
	// Fields are tab-separated; the RDATA keeps its own spacing.
	return strings.Join(strings.SplitN(rr.String(), "\t", 5), " ")
}

type response struct {
	msg *dns.Msg
	err error
}

// send sends the requests of the scenario, in order or all at once.
func send(ctx context.Context, addr string, s *Scenario, zone string) ([]response, error) {
	type job struct {
		request *Request
		msg     *dns.Msg
	}
	var jobs []job
	for i := range s.Requests {
		messages, err := s.Requests[i].Messages(zone)
		if err != nil {
			return nil, fmt.Errorf("request %d: %w", i, err)
		}
		for _, m := range messages {
			jobs = append(jobs, job{request: &s.Requests[i], msg: m})
		}
	}

	responses := make([]response, len(jobs))
	if !s.Parallel {
		for i, j := range jobs {
			responses[i] = exchange(ctx, addr, j.request, j.msg)
		}
		return responses, nil
	}
	var wg sync.WaitGroup
	for i, j := range jobs {
		wg.Go(func() {
			responses[i] = exchange(ctx, addr, j.request, j.msg)
		})
	}
	wg.Wait()
	return responses, nil
}

func exchange(ctx context.Context, addr string, r *Request, m *dns.Msg) response {
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
// provider of miekg/dns, it supports HMAC-MD5.
type hmacProvider []byte

func (p hmacProvider) Generate(msg []byte, t *dns.TSIG) ([]byte, error) {
	var newHash func() hash.Hash
	switch dns.CanonicalName(t.Algorithm) {
	case "hmac-md5.sig-alg.reg.int.":
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

func checkResponses(s *Scenario, zone string, responses []response) []string {
	var problems []string
	for i, r := range responses {
		prefix := fmt.Sprintf("response %d", i)
		if r.msg == nil {
			problems = append(problems, fmt.Sprintf("%s: none received: %v", prefix, r.err))
			continue
		}
		for _, problem := range checkResponse(s, zone, r) {
			problems = append(problems, prefix+": "+problem)
		}
	}
	return problems
}

func checkResponse(s *Scenario, zone string, r response) []string {
	var problems []string
	if got, want := dns.RcodeToString[r.msg.Rcode], s.ExpectedRcode(); got != want {
		problems = append(problems, fmt.Sprintf("rcode %s, want %s", got, want))
	}
	tsig := r.msg.IsTsig()
	if s.Expect.TSIGError != "" {
		switch {
		case tsig == nil:
			problems = append(problems, "no TSIG record, want TSIG error "+s.Expect.TSIGError)
		case dns.RcodeToString[int(tsig.Error)] != s.Expect.TSIGError:
			problems = append(problems, fmt.Sprintf("TSIG error %s, want %s",
				dns.RcodeToString[int(tsig.Error)], s.Expect.TSIGError))
		}
	}
	if s.Expect.SignedResponse {
		switch {
		case tsig == nil:
			problems = append(problems, "not signed")
		case r.err != nil:
			problems = append(problems, fmt.Sprintf("invalid signature: %v", r.err))
		}
	}
	if s.Expect.Authoritative && !r.msg.Authoritative {
		problems = append(problems, "not authoritative")
	}
	for _, section := range []struct {
		name     string
		records  []dns.RR
		expected *[]string
	}{
		{"answer", r.msg.Answer, s.Expect.Answer},
		{"authority", r.msg.Ns, s.Expect.Authority},
	} {
		if section.expected == nil {
			continue
		}
		got := ownersAndTypes(section.records, zone)
		want := slices.Sorted(slices.Values(*section.expected))
		if !slices.Equal(got, want) {
			problems = append(problems, fmt.Sprintf("%s section %q, want %q", section.name, got, want))
		}
	}
	return problems
}

// ownersAndTypes describes records as "<owner> <TYPE>", with owner names
// relative to the zone, sorted.
func ownersAndTypes(records []dns.RR, zone string) []string {
	described := make([]string, 0, len(records))
	for _, rr := range records {
		owner := dns.CanonicalName(rr.Header().Name)
		if owner == zone {
			owner = "@"
		} else {
			owner = strings.TrimSuffix(owner, "."+zone)
		}
		described = append(described, owner+" "+dns.Type(rr.Header().Rrtype).String())
	}
	slices.Sort(described)
	return described
}

// checkRecords compares the zone after the requests with the expected
// records, or with the zone before the requests when the scenario expects no
// change.
func checkRecords(s *Scenario, zone string, initial, final []string) []string {
	want := initial
	if s.Expect.Records != nil {
		expected, err := ParseRecords(*s.Expect.Records, zone)
		if err != nil {
			return []string{err.Error()}
		}
		want = make([]string, 0, len(expected)+1)
		listsApexNS := false
		for _, rr := range expected {
			if rr.Header().Rrtype == dns.TypeNS && dns.CanonicalName(rr.Header().Name) == zone {
				listsApexNS = true
			}
			want = append(want, Normalize(rr))
		}
		if !listsApexNS {
			want = append(want, apexNS(initial, zone)...)
		}
		slices.Sort(want)
	}
	return diffRecords(want, final)
}

// apexNS returns the NS records of the apex among normalized records.
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
