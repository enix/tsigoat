package rfc2136_test

import (
	"context"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/rfc2136"
	"github.com/enix/tsigoat/internal/config"
)

const zone = "example.test."

// relayKey is the key of tsigoat for the name server.
func relayKey() config.Key {
	return config.Key{Name: "tsigoat.", Algorithm: config.HMACSHA256, Secret: []byte("thirty-two bytes of relay secret")}
}

// nameServer is a name server for the tests, which records the requests and
// answers them with its handler.
type nameServer struct {
	addr string

	mu       sync.Mutex
	requests []*dns.Msg
}

func (n *nameServer) last(t *testing.T) *dns.Msg {
	t.Helper()
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.requests) == 0 {
		t.Fatal("the name server received no request")
	}
	return n.requests[len(n.requests)-1]
}

// handler answers a request whose signature verified, through w.
type handler func(w dns.ResponseWriter, req *dns.Msg)

// startNameServer serves on a loopback TCP port with the keys, until the end
// of the test. A request whose signature does not verify gets NOTAUTH with
// BADSIG, as RFC 8945 says.
func startNameServer(t *testing.T, keys []config.Key, h handler) *nameServer {
	t.Helper()
	keyring, err := auth.NewKeyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	n := &nameServer{addr: listener.Addr().String()}
	started := make(chan struct{})
	server := &dns.Server{
		Listener:          listener,
		TsigProvider:      keyring,
		NotifyStartedFunc: func() { close(started) },
		// The default rejects updates.
		MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept },
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
			n.mu.Lock()
			n.requests = append(n.requests, req)
			n.mu.Unlock()
			if tsig := req.IsTsig(); tsig != nil && w.TsigStatus() != nil {
				resp := new(dns.Msg).SetRcode(req, dns.RcodeNotAuth)
				resp.SetTsig(tsig.Hdr.Name, tsig.Algorithm, 300, time.Now().Unix())
				resp.IsTsig().Error = dns.RcodeBadSig
				_ = w.WriteMsg(resp)
				return
			}
			h(w, req)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	<-started
	t.Cleanup(func() { _ = server.Shutdown() })
	return n
}

// reply answers with an rcode, signed with the key of the request.
func reply(rcode int) handler {
	return func(w dns.ResponseWriter, req *dns.Msg) {
		resp := new(dns.Msg).SetRcode(req, rcode)
		sign(resp, req)
		_ = w.WriteMsg(resp)
	}
}

func sign(resp, req *dns.Msg) {
	if tsig := req.IsTsig(); tsig != nil {
		resp.SetTsig(tsig.Hdr.Name, tsig.Algorithm, 300, time.Now().Unix())
	}
}

func newRelay(t *testing.T, server string, timeout time.Duration) *rfc2136.Relay {
	t.Helper()
	r, err := rfc2136.New(&rfc2136.Options{Server: server, Key: relayKey(), Timeout: timeout})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func records(t *testing.T, texts ...string) []dns.RR {
	t.Helper()
	rrs := make([]dns.RR, 0, len(texts))
	for _, text := range texts {
		rr, err := dns.NewRR(text)
		if err != nil {
			t.Fatal(err)
		}
		rrs = append(rrs, rr)
	}
	return rrs
}

func TestUpdateRelaysTheMessage(t *testing.T) {
	t.Parallel()

	server := startNameServer(t, []config.Key{relayKey()}, reply(dns.RcodeSuccess))
	// An update as a client sends it, then as tsigoat decodes it.
	mx := records(t, "mx.example.test. 300 IN MX 10 mail.example.test.")
	sent := new(dns.Msg)
	sent.SetUpdate(zone)
	sent.RRsetNotUsed(records(t, "www.example.test. 0 IN CNAME target.example.test."))
	sent.NameUsed(mx)
	sent.Insert(records(t, "www.example.test. 300 IN A 192.0.2.1"))
	sent.Remove(records(t, `txt.example.test. 300 IN TXT "stale"`))
	sent.RemoveRRset(mx)
	sent.RemoveRRset(records(t, "example.test. 3600 IN SOA ns1. hostmaster. 1 2 3 4 5"))
	sent.RemoveName(records(t, "old.example.test. 300 IN A 192.0.2.2"))
	wire, err := sent.Pack()
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(dns.Msg)
	if unpackErr := decoded.Unpack(wire); unpackErr != nil {
		t.Fatal(unpackErr)
	}

	rcode, err := newRelay(t, server.addr, time.Second).Update(t.Context(), zone, "client.", decoded.Answer, decoded.Ns)
	if err != nil || rcode != dns.RcodeSuccess {
		t.Fatalf("Update() = %s, %v, want NOERROR", dns.RcodeToString[rcode], err)
	}

	req := server.last(t)
	if req.Opcode != dns.OpcodeUpdate || len(req.Question) != 1 ||
		req.Question[0] != (dns.Question{Name: zone, Qtype: dns.TypeSOA, Qclass: dns.ClassINET}) {
		t.Errorf("relayed header and zone = %s %v", dns.OpcodeToString[req.Opcode], req.Question)
	}
	tsig := req.IsTsig()
	if tsig == nil || tsig.Hdr.Name != "tsigoat." || tsig.Algorithm != dns.HmacSHA256 {
		t.Fatalf("relayed signature = %v, want key tsigoat. with hmac-sha256", tsig)
	}
	compare(t, "prerequisite", req.Answer, sent.Answer)
	compare(t, "update", req.Ns, sent.Ns)
	if len(req.Extra) != 1 {
		t.Errorf("additional section = %v, want the TSIG record alone", req.Extra)
	}
}

// compare checks that the relayed records encode as the sent ones.
func compare(t *testing.T, section string, got, want []dns.RR) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d %s records relayed, want %d", len(got), section, len(want))
	}
	for i := range want {
		if g, w := wireFormat(t, section, got[i]), wireFormat(t, section, want[i]); g != w {
			t.Errorf("%s %d encodes as %x, want %x (%v)", section, i, g, w, want[i])
		}
	}
}

// wireFormat encodes a record of a section. The records that RFC 2136 sends
// without RDATA encode without any, as miekg/dns encodes empty fields anyway.
func wireFormat(t *testing.T, section string, rr dns.RR) string {
	t.Helper()
	if class := rr.Header().Class; class == dns.ClassANY || (section == "prerequisite" && class == dns.ClassNONE) {
		rr = &dns.ANY{Hdr: *rr.Header()}
	}
	buf := make([]byte, dns.Len(rr))
	n, err := dns.PackRR(rr, buf, 0, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func TestUpdateRcodes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		rcode int
		// err is a part of the error; the rcode passes through when empty.
		err string
		// indeterminate tells that the server may have applied the update:
		// miekg/dns does not verify a NOTAUTH response.
		indeterminate bool
	}{
		{dns.RcodeSuccess, "", false},
		{dns.RcodeYXDomain, "", false},
		{dns.RcodeYXRrset, "", false},
		{dns.RcodeNameError, "", false},
		{dns.RcodeNXRrset, "", false},
		{dns.RcodeFormatError, "", false},
		{dns.RcodeNotZone, "", false},
		{dns.RcodeRefused, "refused the update of zone example.test.: grant key tsigoat.", false},
		{dns.RcodeNotAuth, "answered NOTAUTH: it is not authoritative for zone example.test.", true},
		{dns.RcodeNotImplemented, "does not implement updates", false},
		{dns.RcodeServerFailure, "answered the update of zone example.test. with SERVFAIL", false},
		{12, "with RCODE12", false},
	}
	for _, tt := range tests {
		t.Run(rcodeName(tt.rcode), func(t *testing.T) {
			t.Parallel()
			server := startNameServer(t, []config.Key{relayKey()}, reply(tt.rcode))
			rcode, err := newRelay(t, server.addr, time.Second).Update(t.Context(), zone, "", nil, nil)
			switch {
			case tt.err == "" && (err != nil || rcode != tt.rcode):
				t.Errorf("Update() = %s, %v, want %s", rcodeName(rcode), err, rcodeName(tt.rcode))
			case tt.err != "" && (err == nil || !strings.Contains(err.Error(), tt.err)):
				t.Errorf("Update() error = %v, want one about %q", err, tt.err)
			}
			if backend.IsIndeterminate(err) != tt.indeterminate {
				t.Errorf("Update() error = %v, indeterminate %t, want %t", err, backend.IsIndeterminate(err), tt.indeterminate)
			}
		})
	}
}

func rcodeName(rcode int) string {
	if name, ok := dns.RcodeToString[rcode]; ok {
		return name
	}
	return "unassigned"
}

func TestExchangeFailures(t *testing.T) {
	t.Parallel()

	other := config.Key{Name: "other.", Algorithm: config.HMACSHA256, Secret: []byte("thirty-two bytes of other secret")}
	wrongSecret := relayKey()
	wrongSecret.Secret = []byte("thirty-two bytes, but not these!")
	tests := []struct {
		name    string
		keys    []config.Key
		handler handler
		err     string
		// indeterminate tells that the server may have applied the update.
		indeterminate bool
	}{
		// The server answers NOTAUTH with BADSIG, unsigned: so would anyone.
		{"wrong secret", []config.Key{wrongSecret}, reply(dns.RcodeSuccess), "rejected the signature of key tsigoat.: BADSIG", true},
		// A response without signature may come from a server that applied
		// the update, or from anyone.
		{"unsigned response", []config.Key{relayKey()}, func(w dns.ResponseWriter, req *dns.Msg) {
			_ = w.WriteMsg(new(dns.Msg).SetRcode(req, dns.RcodeSuccess))
		}, "answered NOERROR without signing", true},
		{"response signed with another key", []config.Key{relayKey(), other}, func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg).SetRcode(req, dns.RcodeSuccess)
			resp.SetTsig("other.", dns.HmacSHA256, 300, time.Now().Unix())
			_ = w.WriteMsg(resp)
		}, "does not verify", true},
		{"connection closed without a response", []config.Key{relayKey()}, func(w dns.ResponseWriter, _ *dns.Msg) {
			_ = w.Close()
		}, "exchanging with", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := startNameServer(t, tt.keys, tt.handler)
			_, err := newRelay(t, server.addr, time.Second).Update(t.Context(), zone, "", nil, nil)
			if err == nil || !strings.Contains(err.Error(), tt.err) {
				t.Errorf("Update() error = %v, want one about %q", err, tt.err)
			}
			if backend.IsIndeterminate(err) != tt.indeterminate {
				t.Errorf("Update() error = %v, indeterminate %t, want %t", err, backend.IsIndeterminate(err), tt.indeterminate)
			}
		})
	}
}

func TestTimeout(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	server := startNameServer(t, []config.Key{relayKey()}, func(dns.ResponseWriter, *dns.Msg) { <-release })
	// Cleanups run last first: the handler returns before the server stops.
	t.Cleanup(func() { close(release) })

	start := time.Now()
	relay := newRelay(t, server.addr, 100*time.Millisecond)
	_, err := relay.Update(t.Context(), zone, "", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "exchanging with "+server.addr) {
		t.Errorf("Update() error = %v, want a timeout", err)
	}
	// The server received the update, and may apply it after the timeout.
	if !backend.IsIndeterminate(err) {
		t.Errorf("Update() error = %v, want an unknown outcome", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("Update() returned after %s, beyond its timeout", elapsed)
	}
	// A query that times out changes nothing.
	if _, err := relay.SOA(t.Context(), zone); err == nil || backend.IsIndeterminate(err) {
		t.Errorf("SOA() error = %v, want a plain timeout", err)
	}
}

func TestUnreachable(t *testing.T) {
	t.Parallel()

	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	_, err = newRelay(t, addr, time.Second).Update(t.Context(), zone, "", nil, nil)
	if err == nil {
		t.Error("Update() succeeded without a server")
	}
	// Nothing reached a server.
	if backend.IsIndeterminate(err) {
		t.Errorf("Update() error = %v, want a plain failure", err)
	}
}

func TestSOA(t *testing.T) {
	t.Parallel()

	soa := records(t, "example.test. 3600 IN SOA ns1.example.test. hostmaster.example.test. 7 10800 3600 604800 3600")[0]
	answer := func(rcode int, authoritative bool, rrs ...dns.RR) handler {
		return func(w dns.ResponseWriter, req *dns.Msg) {
			resp := new(dns.Msg).SetRcode(req, rcode)
			resp.Authoritative = authoritative
			resp.Answer = rrs
			sign(resp, req)
			_ = w.WriteMsg(resp)
		}
	}

	server := startNameServer(t, []config.Key{relayKey()}, answer(dns.RcodeSuccess, true, soa))
	got, err := newRelay(t, server.addr, time.Second).SOA(t.Context(), zone)
	if err != nil || !dns.IsDuplicate(got, soa) {
		t.Fatalf("SOA() = %v, %v, want %v", got, err, soa)
	}
	if req := server.last(t); req.Question[0].Qtype != dns.TypeSOA || req.RecursionDesired || req.IsTsig() == nil {
		t.Errorf("SOA query = %v, want a signed, non-recursive SOA query", req)
	}

	failures := []struct {
		name    string
		handler handler
		err     string
	}{
		{"not authoritative", answer(dns.RcodeSuccess, false, soa), "is not authoritative for zone example.test."},
		{"rcode", answer(dns.RcodeRefused, true), "answered the SOA query of example.test. with REFUSED"},
		{"no SOA", answer(dns.RcodeSuccess, true), "without its SOA"},
	}
	for _, tt := range failures {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			server := startNameServer(t, []config.Key{relayKey()}, tt.handler)
			if _, err := newRelay(t, server.addr, time.Second).SOA(t.Context(), zone); err == nil ||
				!strings.Contains(err.Error(), tt.err) {
				t.Errorf("SOA() error = %v, want one about %q", err, tt.err)
			}
		})
	}
}

func TestNew(t *testing.T) {
	t.Parallel()

	if _, err := rfc2136.New(&rfc2136.Options{Server: "ns1.example.test", Key: relayKey()}); err == nil {
		t.Error("New() accepted a server without a port")
	}
	if _, err := rfc2136.New(&rfc2136.Options{Server: "ns1.example.test:53", Key: config.Key{Name: "k."}}); err == nil {
		t.Error("New() accepted a key without a secret")
	}
}

func TestContextCanceled(t *testing.T) {
	t.Parallel()

	server := startNameServer(t, []config.Key{relayKey()}, reply(dns.RcodeSuccess))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newRelay(t, server.addr, time.Second).Update(ctx, zone, "", nil, nil); err == nil {
		t.Error("Update() succeeded with a canceled context")
	}
}

// TestCanceledInFlight checks an update canceled while the server holds it:
// the server received it, and may apply it still.
func TestCanceledInFlight(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	server := startNameServer(t, []config.Key{relayKey()}, func(dns.ResponseWriter, *dns.Msg) { <-release })
	t.Cleanup(func() { close(release) })
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	if _, err := newRelay(t, server.addr, time.Second).Update(ctx, zone, "", nil, nil); !backend.IsIndeterminate(err) {
		t.Errorf("Update() error = %v, want an unknown outcome", err)
	}
}
