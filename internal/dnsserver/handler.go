package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/auth"
	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/update"
	"github.com/enix/tsigoat/internal/zone"
)

const (
	// fudge is the clock error, in seconds, that the signature of a response
	// tolerates.
	fudge = 300
	// ednsUDPSize is the UDP payload size advertised to EDNS clients, as
	// recommended by the DNS flag day 2020.
	ednsUDPSize = 1232
)

// exchange is a request being processed.
type exchange struct {
	w   dns.ResponseWriter
	req *dns.Msg
	// identity is the key that signed the request, or auth.Unauthenticated.
	identity string
	// tsig is the TSIG record of a signed request whose signature is valid.
	tsig   *dns.TSIG
	logger *slog.Logger
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	// A request runs to completion even when the server shuts down.
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	ex := &exchange{w: w, req: req, identity: auth.Unauthenticated, logger: s.logger}
	if addr := w.RemoteAddr(); addr != nil {
		ex.logger = ex.logger.With("remote", addr.String())
	}
	resp := s.handle(ctx, ex)
	if err := w.WriteMsg(resp); err != nil {
		ex.logger.WarnContext(ctx, "writing the response failed", "error", err)
	}
}

func (s *Server) handle(ctx context.Context, ex *exchange) *dns.Msg {
	if reason := misplaced(ex.req); reason != "" {
		ex.logger.InfoContext(ctx, "malformed request", "reason", reason)
		return ex.reply(dns.RcodeFormatError)
	}
	if tsig := ex.req.IsTsig(); tsig != nil {
		if err := ex.w.TsigStatus(); err != nil {
			return s.tsigFailure(ctx, ex, tsig, err)
		}
		ex.identity = dns.CanonicalName(tsig.Hdr.Name)
		ex.tsig = tsig
		ex.logger = ex.logger.With("key", ex.identity)
	}
	if opt := ex.req.IsEdns0(); opt != nil && opt.Version() != 0 {
		return ex.reply(dns.RcodeBadVers)
	}

	switch ex.req.Opcode {
	case dns.OpcodeUpdate:
		return s.update(ctx, ex)
	case dns.OpcodeQuery:
		return s.query(ctx, ex)
	default:
		ex.logger.DebugContext(ctx, "unsupported opcode", "opcode", dns.OpcodeToString[ex.req.Opcode])
		return ex.reply(dns.RcodeNotImplemented)
	}
}

// misplaced returns why the TSIG or OPT records of a message are misplaced,
// or "". RFC 8945 5.1 and RFC 6891 6.1.1 answer such messages FORMERR.
func misplaced(m *dns.Msg) string {
	for _, section := range [][]dns.RR{m.Answer, m.Ns} {
		for _, rr := range section {
			if rrtype := rr.Header().Rrtype; rrtype == dns.TypeTSIG || rrtype == dns.TypeOPT {
				return dns.Type(rrtype).String() + " record outside the additional section"
			}
		}
	}
	opts := 0
	for i, rr := range m.Extra {
		switch rr.Header().Rrtype {
		case dns.TypeTSIG:
			if i != len(m.Extra)-1 {
				return "TSIG record before the end of the additional section"
			}
		case dns.TypeOPT:
			opts++
		}
	}
	if opts > 1 {
		return "several OPT records"
	}
	return ""
}

// response returns an unsigned response to the request.
func (ex *exchange) response(rcode int) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetRcode(ex.req, rcode)
	if ex.req.IsEdns0() != nil {
		resp.SetEdns0(ednsUDPSize, false)
	}
	return resp
}

// reply returns the response to the request, signed if the request was.
func (ex *exchange) reply(rcode int) *dns.Msg {
	resp := ex.response(rcode)
	if ex.tsig != nil {
		resp.SetTsig(ex.tsig.Hdr.Name, ex.tsig.Algorithm, fudge, time.Now().Unix())
	}
	return resp
}

// tsigFailure answers a request whose signature does not verify: NOTAUTH
// with the TSIG error, unsigned unless the error is BADTIME (RFC 8945 5.2,
// 5.3.2).
func (s *Server) tsigFailure(ctx context.Context, ex *exchange, tsig *dns.TSIG, err error) *dns.Msg {
	code := auth.TSIGError(err)
	attrs := []any{
		"key", dns.CanonicalName(tsig.Hdr.Name),
		"algorithm", dns.CanonicalName(tsig.Algorithm),
		"tsig_error", dns.RcodeToString[int(code)],
		"error", err,
	}
	if expected, ok := s.keyring.Algorithm(tsig.Hdr.Name); ok && errors.Is(err, auth.ErrAlgorithmMismatch) {
		attrs = append(attrs, "expected_algorithm", expected)
	}
	ex.logger.WarnContext(ctx, "TSIG verification failed", attrs...)

	resp := ex.response(dns.RcodeNotAuth)
	now := time.Now().Unix()
	resp.SetTsig(tsig.Hdr.Name, tsig.Algorithm, fudge, now)
	rr := resp.IsTsig()
	rr.Error = code
	if code == dns.RcodeBadTime {
		// Signed at the time of the request, so that the client accepts it,
		// with the time of the server for the client to see the offset.
		rr.TimeSigned = tsig.TimeSigned
		rr.OtherLen = 6
		rr.OtherData = fmt.Sprintf("%012x", now)
	}
	return resp
}

// outcome is the result of an update, for the response and the audit log.
type outcome struct {
	zone  string
	rcode int
	// reason explains a rejection.
	reason string
	// err is a failure of tsigoat or of the backend, answered SERVFAIL.
	err     error
	changes []backend.Change
}

func (o *outcome) refuse(reason string) {
	o.rcode, o.reason = dns.RcodeRefused, reason
}

// reject records an error of the update engine.
func (o *outcome) reject(err error) {
	var rejection *update.Error
	if errors.As(err, &rejection) {
		o.rcode, o.reason = rejection.Rcode, rejection.Reason
		return
	}
	o.fail(err)
}

func (o *outcome) fail(err error) {
	o.rcode, o.err = dns.RcodeServerFailure, err
}

// update processes an UPDATE request, and logs its outcome.
func (s *Server) update(ctx context.Context, ex *exchange) *dns.Msg {
	start := time.Now()
	var out outcome
	s.processUpdate(ctx, ex, &out)

	attrs := []any{"zone", out.zone, "rcode", dns.RcodeToString[out.rcode], "duration", time.Since(start)}
	if out.reason != "" {
		attrs = append(attrs, "reason", out.reason)
	}
	if out.err != nil {
		attrs = append(attrs, "error", out.err)
	}
	if len(out.changes) > 0 {
		changes := make([]string, 0, len(out.changes))
		for _, change := range out.changes {
			changes = append(changes, change.String())
		}
		attrs = append(attrs, "changes", changes)
	}
	level := slog.LevelInfo
	switch out.rcode {
	case dns.RcodeServerFailure:
		level = slog.LevelError
	case dns.RcodeRefused, dns.RcodeFormatError, dns.RcodeNotZone:
		level = slog.LevelWarn
	}
	ex.logger.Log(ctx, level, "update", attrs...)

	return ex.reply(out.rcode)
}

// processUpdate checks, authorizes and applies an update, following the
// steps of RFC 2136 3: the backend sees one atomic change, or none.
func (s *Server) processUpdate(ctx context.Context, ex *exchange, out *outcome) {
	zoneName, class, err := update.ParseZone(ex.req)
	if err != nil {
		out.reject(err)
		return
	}
	out.zone = zoneName
	z, rcode, reason := s.admit(ex.identity, zoneName, class)
	if z == nil {
		out.rcode, out.reason = rcode, reason
		return
	}

	req, err := update.Parse(ex.req, zoneName, class, s.served)
	if err != nil {
		out.reject(err)
		return
	}
	if reason := authorize(z.Policy, ex.identity, req); reason != "" {
		out.refuse(reason)
		return
	}

	if err := z.acquire(ctx); err != nil {
		out.fail(err)
		return
	}
	defer z.release()

	view := zone.NewView(z.Backend, zoneName)
	if err := update.CheckPrerequisites(ctx, view, req); err != nil {
		out.reject(err)
		return
	}
	if err := update.Apply(ctx, view, req); err != nil {
		out.fail(err)
		return
	}
	out.changes = view.Changes()
	if len(out.changes) > 0 {
		if err := z.Backend.Apply(ctx, zoneName, out.changes); err != nil {
			out.fail(fmt.Errorf("applying the changes: %w", err))
			return
		}
	}
	out.rcode = dns.RcodeSuccess
}

// admit returns the zone that an update names, or the rcode and the reason
// that turn the update down. Unsigned requests get the same answer for
// unknown zones and forbidden zones, which does not tell which zones tsigoat
// serves.
func (s *Server) admit(identity, zoneName string, class uint16) (z *servedZone, rcode int, reason string) {
	z = s.zones[zoneName]
	switch {
	case (z == nil || class != dns.ClassINET) && identity != auth.Unauthenticated:
		// RFC 2136 3.1.2: a key holder learns that the zone is not served.
		return nil, dns.RcodeNotAuth, "zone not served"
	case z == nil || class != dns.ClassINET:
		return nil, dns.RcodeRefused, "zone not served"
	case !z.Policy.Admits(identity) && identity == auth.Unauthenticated:
		return nil, dns.RcodeRefused, "the zone does not accept unsigned updates"
	case !z.Policy.Admits(identity):
		return nil, dns.RcodeRefused, "the key may not update the zone"
	default:
		return z, dns.RcodeSuccess, ""
	}
}

// authorize returns why the policy refuses a request, or "".
func authorize(policy *auth.Policy, identity string, req *update.Request) string {
	for _, rr := range req.Updates {
		h := rr.Header()
		name := dns.CanonicalName(h.Name)
		allowed := policy.AllowsUpdate(identity, name, h.Rrtype)
		if h.Rrtype == dns.TypeSOA && h.Class != req.Class {
			// The engine ignores the deletion of the SOA, which needs no
			// right on the SOA itself.
			allowed = policy.AllowsName(identity, name)
		}
		if !allowed {
			return "the policy does not allow update " + update.Describe(rr)
		}
	}
	for _, rr := range req.Prerequisites {
		if !policy.AllowsName(identity, dns.CanonicalName(rr.Header().Name)) {
			return "the policy does not allow prerequisite " + update.Describe(rr)
		}
	}
	return ""
}

// query answers the SOA queries that clients such as certbot and nsupdate
// send to find the zone of a name: the SOA comes in the answer section for
// the apex, in the authority section below it. Other queries are not
// implemented.
func (s *Server) query(ctx context.Context, ex *exchange) *dns.Msg {
	if len(ex.req.Question) != 1 {
		return ex.reply(dns.RcodeFormatError)
	}
	q := ex.req.Question[0]
	name := dns.CanonicalName(q.Name)
	zoneName := update.ZoneOf(name, s.served)
	z := s.zones[zoneName]
	if z == nil || q.Qclass != dns.ClassINET || !z.Policy.Admits(ex.identity) {
		ex.logger.DebugContext(ctx, "query refused", "name", name, "type", dns.Type(q.Qtype).String())
		return ex.reply(dns.RcodeRefused)
	}
	if q.Qtype != dns.TypeSOA {
		ex.logger.DebugContext(ctx, "query not implemented", "name", name, "type", dns.Type(q.Qtype).String())
		return ex.reply(dns.RcodeNotImplemented)
	}

	soa, err := lookupSOA(ctx, z)
	if err != nil {
		ex.logger.ErrorContext(ctx, "reading the SOA failed", "zone", zoneName, "error", err)
		return ex.reply(dns.RcodeServerFailure)
	}
	resp := ex.reply(dns.RcodeSuccess)
	resp.Authoritative = true
	if name == zoneName {
		resp.Answer = []dns.RR{soa}
	} else {
		resp.Ns = []dns.RR{soa}
	}
	ex.logger.DebugContext(ctx, "SOA query answered", "name", name, "zone", zoneName)
	return resp
}

func lookupSOA(ctx context.Context, z *servedZone) (dns.RR, error) {
	sets, err := z.Backend.Lookup(ctx, z.Name, z.Name)
	if err != nil {
		return nil, fmt.Errorf("looking up the apex of %s: %w", z.Name, err)
	}
	for _, set := range sets {
		if set.Type == dns.TypeSOA && len(set.Records) > 0 {
			soa := dns.Copy(set.Records[0])
			soa.Header().Name = z.Name
			soa.Header().Ttl = set.TTL
			return soa, nil
		}
	}
	return nil, fmt.Errorf("zone %s has no SOA", z.Name)
}
