// Package rfc2136 relays DNS updates to a name server that implements RFC
// 2136 itself, such as BIND or Knot DNS, signed with a TSIG key of tsigoat.
//
// The server evaluates the prerequisites and applies the update atomically:
// tsigoat checks the structure of an update and its policy, relays it whole,
// and relays the outcome to the client. The rcodes that tell the client about
// its own update pass through: NOERROR, the failed prerequisites (YXDOMAIN,
// YXRRSET, NXDOMAIN, NXRRSET), FORMERR and NOTZONE. The others tell of a
// server, or of a configuration, that the operator of tsigoat must fix: a
// REFUSED update, for one, means that the server does not grant tsigoat what
// its policy grants the client. They are errors, which the client gets as
// SERVFAIL.
package rfc2136

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/config"
)

const (
	// DefaultTimeout bounds every exchange with the server when Options set
	// none.
	DefaultTimeout = 5 * time.Second
	// fudge is the clock error, in seconds, that the signatures tolerate.
	fudge = 300
)

// Options configure a relay.
type Options struct {
	// Server is the host:port of the name server.
	Server string
	// Key signs the messages to the server, and verifies its responses.
	Key config.Key
	// Timeout bounds every exchange with the server; DefaultTimeout when
	// zero.
	Timeout time.Duration
}

// Relay sends the updates and the SOA queries of its zones to a name server,
// over TCP.
type Relay struct {
	server    string
	keyName   string
	algorithm string
	keyring   *auth.Keyring
	timeout   time.Duration
}

var _ backend.Relay = (*Relay)(nil)

// New returns a relay to a name server.
func New(o *Options) (*Relay, error) {
	if _, _, err := net.SplitHostPort(o.Server); err != nil {
		return nil, fmt.Errorf("server %q: %w", o.Server, err)
	}
	keyring, err := auth.NewKeyring([]config.Key{o.Key})
	if err != nil {
		return nil, fmt.Errorf("loading the key: %w", err)
	}
	keyName := dns.CanonicalName(o.Key.Name)
	algorithm, _ := keyring.Algorithm(keyName)
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	return &Relay{server: o.Server, keyName: keyName, algorithm: algorithm, keyring: keyring, timeout: timeout}, nil
}

// Update implements backend.Relay. The server sees the updates coming from
// the key of tsigoat, whatever the key of the client.
func (r *Relay) Update(ctx context.Context, zone, _ string, prerequisites, updates []dns.RR) (int, error) {
	m := new(dns.Msg)
	m.SetUpdate(zone)
	m.Answer = withoutRDATA(prerequisites, true)
	m.Ns = withoutRDATA(updates, false)
	resp, err := r.exchange(ctx, zone, m)
	if err != nil {
		return 0, err
	}
	if resp.Opcode != dns.OpcodeUpdate {
		return 0, fmt.Errorf("%s answered the update with opcode %s", r.server, dns.OpcodeToString[resp.Opcode])
	}

	switch resp.Rcode {
	case dns.RcodeSuccess,
		dns.RcodeYXDomain, dns.RcodeYXRrset, dns.RcodeNameError, dns.RcodeNXRrset,
		dns.RcodeFormatError, dns.RcodeNotZone:
		return resp.Rcode, nil
	case dns.RcodeRefused:
		return 0, fmt.Errorf("%s refused the update of zone %s: grant key %s the right to make it",
			r.server, zone, r.keyName)
	case dns.RcodeNotImplemented:
		return 0, fmt.Errorf("%s does not implement updates", r.server)
	default:
		return 0, fmt.Errorf("%s answered the update of zone %s with %s", r.server, zone, rcodeName(resp.Rcode))
	}
}

// SOA implements backend.Relay.
func (r *Relay) SOA(ctx context.Context, zone string) (dns.RR, error) {
	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeSOA)
	m.RecursionDesired = false
	resp, err := r.exchange(ctx, zone, m)
	if err != nil {
		return nil, err
	}
	switch {
	case resp.Rcode != dns.RcodeSuccess:
		return nil, fmt.Errorf("%s answered the SOA query of %s with %s", r.server, zone, rcodeName(resp.Rcode))
	case !resp.Authoritative:
		return nil, fmt.Errorf("%s is not authoritative for zone %s", r.server, zone)
	}
	for _, rr := range resp.Answer {
		if soa, ok := rr.(*dns.SOA); ok && dns.CanonicalName(soa.Hdr.Name) == zone {
			return soa, nil
		}
	}
	return nil, fmt.Errorf("%s answered the SOA query of %s without its SOA", r.server, zone)
}

// Check implements backend.Relay: it queries the SOA of the zone, signed,
// which checks that the server answers for the zone and knows the key.
func (r *Relay) Check(ctx context.Context, zone string) error {
	_, err := r.SOA(ctx, zone)
	return err
}

// exchange signs a message about a zone, sends it over TCP, and returns the
// response once its signature verifies.
func (r *Relay) exchange(ctx context.Context, zone string, m *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	m.SetTsig(r.keyName, r.algorithm, fudge, time.Now().Unix())
	client := &dns.Client{Net: "tcp", Timeout: r.timeout, TsigProvider: r.keyring}

	resp, _, err := client.ExchangeContext(ctx, m, r.server)
	if resp != nil {
		// The server signs a response with a TSIG error when it can, or
		// leaves its MAC empty, which fails the verification.
		if tsig := resp.IsTsig(); tsig != nil && tsig.Error != dns.RcodeSuccess {
			return nil, fmt.Errorf("%s rejected the signature of key %s: %s", r.server, r.keyName, rcodeName(int(tsig.Error)))
		}
	}
	switch {
	case errors.Is(err, dns.ErrAuth) && resp != nil && resp.Rcode == dns.RcodeNotAuth:
		// miekg/dns leaves the signature of a NOTAUTH response unverified.
		return nil, fmt.Errorf("%s answered NOTAUTH: it is not authoritative for zone %s", r.server, zone)
	case errors.Is(err, dns.ErrSig), errors.Is(err, dns.ErrTime), errors.Is(err, auth.ErrUnknownKey),
		errors.Is(err, auth.ErrAlgorithmMismatch):
		return nil, fmt.Errorf("the response of %s does not verify: %w", r.server, err)
	case err != nil:
		return nil, fmt.Errorf("exchanging with %s: %w", r.server, err)
	case resp.IsTsig() == nil:
		// Only a server that cannot verify the request answers unsigned.
		return nil, fmt.Errorf("%s answered %s without signing", r.server, rcodeName(resp.Rcode))
	}
	return resp, nil
}

// withoutRDATA returns the records of a section, those that carry no RDATA by
// RFC 2136 rewritten so that they encode without any: miekg/dns decodes them
// into records of their type with empty fields, and some types would encode
// fields anyway, such as the preference of an MX record. Records of class ANY
// carry no RDATA, nor prerequisites of class NONE.
func withoutRDATA(rrs []dns.RR, prerequisites bool) []dns.RR {
	out := make([]dns.RR, len(rrs))
	for i, rr := range rrs {
		h := *rr.Header()
		if h.Class == dns.ClassANY || (prerequisites && h.Class == dns.ClassNONE) {
			h.Rdlength = 0
			out[i] = &dns.ANY{Hdr: h}
			continue
		}
		out[i] = rr
	}
	return out
}

// rcodeName returns the mnemonic of an rcode, or its number.
func rcodeName(rcode int) string {
	if name, ok := dns.RcodeToString[rcode]; ok {
		return name
	}
	return fmt.Sprintf("RCODE%d", rcode)
}
