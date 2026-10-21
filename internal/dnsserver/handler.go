package dnsserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
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
	// ednsUDPSize is the UDP payload size advertised to EDNS clients, and the
	// largest response sent over UDP, as recommended by the DNS flag day 2020
	// against IP fragmentation.
	ednsUDPSize = 1232
)

// exchange is a request being processed.
type exchange struct {
	w   dns.ResponseWriter
	req *dns.Msg
	// identity is the key that signed the request, or auth.Unauthenticated.
	identity string
	// tsig is the TSIG record of a signed request whose signature is valid.
	tsig *dns.TSIG
	// tsigError is the TSIG error of a request whose signature does not
	// verify, which the response carries: WriteMsg takes the TSIG record out
	// of the response as it signs it, before the observer sees it.
	tsigError uint16
	// zone is the served zone that the request names, once known.
	zone   string
	logger *slog.Logger
}

// ServeDNS implements dns.Handler.
func (s *Server) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	// A request runs to completion even when the server shuts down.
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	ex := &exchange{w: w, req: req, identity: auth.Unauthenticated, logger: s.logger}
	if addr := w.RemoteAddr(); addr != nil {
		ex.logger = ex.logger.With("remote", addr.String())
	}
	resp := s.handle(ctx, ex)
	if _, tcp := w.RemoteAddr().(*net.TCPAddr); !tcp {
		s.fit(resp, udpSize(req))
	}
	if err := w.WriteMsg(resp); err != nil {
		ex.logger.WarnContext(ctx, "writing the response failed", "error", err)
	}
	if s.observer != nil {
		s.observer.Observe(ex.answer(resp, time.Since(start)))
	}
}

// answer describes the response to the request, for the observer.
func (ex *exchange) answer(resp *dns.Msg, elapsed time.Duration) *Answer {
	a := &Answer{
		Opcode:   dns.OpcodeToString[ex.req.Opcode],
		Rcode:    dns.RcodeToString[resp.Rcode],
		Zone:     ex.zone,
		Key:      ex.identity,
		Duration: elapsed,
	}
	if a.Opcode == "" {
		a.Opcode = "OPCODE" + strconv.Itoa(ex.req.Opcode)
	}
	if ex.tsig != nil {
		a.Algorithm = dns.CanonicalName(ex.tsig.Algorithm)
	}
	if ex.tsigError != dns.RcodeSuccess {
		a.TSIGError = dns.RcodeToString[int(ex.tsigError)]
	}
	return a
}

func (s *Server) handle(ctx context.Context, ex *exchange) *dns.Msg {
	if reason := misplaced(ex.req); reason != "" {
		ex.logger.InfoContext(ctx, "malformed request", "reason", reason)
		return ex.reply(dns.RcodeFormatError)
	}
	if tsig := ex.req.IsTsig(); tsig != nil {
		err := ex.w.TsigStatus()
		if errors.Is(err, auth.ErrMACSize) {
			// RFC 8945 5.2.2.1: the message is corrupt.
			ex.logger.InfoContext(ctx, "malformed request", "reason", err.Error())
			return ex.reply(dns.RcodeFormatError)
		}
		if err == nil {
			// RFC 8945 5.2: the truncation policy comes last, once the MAC
			// and the time verified.
			err = s.keyring.CheckTruncation(tsig)
		}
		if err != nil {
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

// udpSize returns the size of the largest response to a request over UDP:
// 512 octets without EDNS (RFC 1035 4.2.1), the payload size that the
// requester advertises with EDNS, from 512 octets up to ednsUDPSize
// (RFC 6891 6.2.3, 6.2.5).
func udpSize(req *dns.Msg) int {
	opt := req.IsEdns0()
	if opt == nil {
		return dns.MinMsgSize
	}
	return min(max(int(opt.UDPSize()), dns.MinMsgSize), ednsUDPSize)
}

// fit makes a response over UDP fit in size octets, the TSIG record that
// WriteMsg signs included: it compresses the response if need be, then keeps
// only its question and its OPT and TSIG records, with TC set for the client
// to retry over TCP (RFC 2181 9), as RFC 8945 5.3 truncates a signed
// response. Only the answers to SOA queries hold other records: a response
// that still does not fit answers a request about as large.
func (s *Server) fit(resp *dns.Msg, size int) {
	if tsig := resp.IsTsig(); tsig != nil {
		// WriteMsg packs the response without its TSIG record, then appends
		// the record signed.
		size -= s.signedLen(tsig)
		resp.Extra = resp.Extra[:len(resp.Extra)-1]
		defer func() { resp.Extra = append(resp.Extra, tsig) }()
	}
	if resp.Len() <= size {
		return
	}
	resp.Compress = true
	if resp.Len() <= size {
		return
	}
	opt := resp.IsEdns0()
	resp.Answer, resp.Ns, resp.Extra = nil, nil, nil
	if opt != nil {
		resp.Extra = []dns.RR{opt}
	}
	resp.Truncated = true
}

// signedLen returns the length of a TSIG record once WriteMsg signs it, with
// the full MAC of its key; it signs neither BADKEY nor BADSIG.
func (s *Server) signedLen(tsig *dns.TSIG) int {
	signed := *tsig
	if tsig.Error != dns.RcodeBadKey && tsig.Error != dns.RcodeBadSig {
		signed.MAC = strings.Repeat("00", s.keyring.MACSize(tsig))
	}
	return dns.Len(&signed)
}

// tsigFailure answers a request whose signature does not verify: NOTAUTH
// with the TSIG error, unsigned for BADKEY and BADSIG, signed for BADTIME and
// BADTRUNC (RFC 8945 5.2, 5.3.2), which miekg/dns does when it writes the
// response.
func (s *Server) tsigFailure(ctx context.Context, ex *exchange, tsig *dns.TSIG, err error) *dns.Msg {
	code := auth.TSIGError(err)
	ex.tsigError = code
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
	// raised lists the RRsets whose TTL the server raised to the minimum
	// of the backend.
	raised []string
	// relayed holds the updates relayed to the relay of the zone, whose
	// effect tsigoat does not know.
	relayed []dns.RR
}

func (o *outcome) refuse(reason string) {
	o.rcode, o.reason = dns.RcodeRefused, reason
}

// reject records an error of the update engine.
func (o *outcome) reject(err error) {
	if rejection, ok := errors.AsType[*update.Error](err); ok {
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
	if len(out.raised) > 0 {
		attrs = append(attrs, "ttl_raised", out.raised)
	}
	if len(out.relayed) > 0 {
		updates := make([]string, 0, len(out.relayed))
		for _, rr := range out.relayed {
			updates = append(updates, update.Operation(rr))
		}
		attrs = append(attrs, "updates", updates)
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
	if _, served := s.zones[zoneName]; served {
		ex.zone = zoneName
	}
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
	if reason := z.Policy.Authorize(ex.identity, req.Class, req.Prerequisites, req.Updates); reason != "" {
		out.refuse(reason)
		return
	}
	if z.Relay != nil {
		relay(ctx, z, ex.identity, req, out)
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
	out.raised = raiseTTLs(out.changes, z.MinTTL)
	if len(out.changes) > 0 {
		err := z.Backend.Apply(ctx, zoneName, out.changes)
		if rejection, ok := errors.AsType[*backend.RejectionError](err); ok {
			out.rcode, out.reason = rejection.Rcode, rejection.Reason
			return
		}
		if err != nil {
			out.fail(fmt.Errorf("applying the changes: %w", err))
			return
		}
	}
	out.rcode = dns.RcodeSuccess
}

// raiseTTLs raises the TTLs of the RRsets that the changes replace or add to
// the minimum of the backend, and returns those it raised, such as
// "www.example.org. TXT 0 to 60".
func raiseTTLs(changes []backend.Change, minTTL uint32) []string {
	var raised []string
	for i := range changes {
		set := &changes[i].RRset
		if (changes[i].Op != backend.Replace && changes[i].Op != backend.Add) || set.TTL >= minTTL {
			continue
		}
		raised = append(raised, fmt.Sprintf("%s %s %d to %d", set.Name, dns.Type(set.Type), set.TTL, minTTL))
		set.TTL = minTTL
		for _, rr := range set.Records {
			rr.Header().Ttl = minTTL
		}
	}
	return raised
}

// relay hands an authorized update over to the relay of its zone, which
// evaluates its prerequisites and applies it: tsigoat neither reads the zone
// nor serializes its updates.
func relay(ctx context.Context, z *servedZone, identity string, req *update.Request, out *outcome) {
	out.relayed = req.Updates
	rcode, err := z.Relay.Update(ctx, z.Name, identity, req.Prerequisites, req.Updates)
	if rejection, ok := errors.AsType[*backend.RejectionError](err); ok {
		out.rcode, out.reason = rejection.Rcode, rejection.Reason
		return
	}
	if err != nil {
		out.fail(fmt.Errorf("relaying the update: %w", err))
		return
	}
	out.rcode = rcode
	if rcode != dns.RcodeSuccess {
		out.reason = "answered by the server of backend " + z.BackendName
	}
}

// admit returns the zone that an update names, or the rcode and the reason
// that turn the update down. Unsigned updates get the same answer for unknown
// zones and forbidden zones; the SOA queries tell which zones tsigoat serves
// anyway, as lego and certbot need.
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

// query answers the SOA queries that clients send to find the zone of a
// name: the SOA comes in the answer section for the apex, in the authority
// section below it. lego and certbot send them unsigned, so that tsigoat
// answers them whatever the signature. Other queries are not implemented.
func (s *Server) query(ctx context.Context, ex *exchange) *dns.Msg {
	if len(ex.req.Question) != 1 {
		return ex.reply(dns.RcodeFormatError)
	}
	q := ex.req.Question[0]
	name := dns.CanonicalName(q.Name)
	zoneName := update.ZoneOf(name, s.served)
	z := s.zones[zoneName]
	if z == nil || q.Qclass != dns.ClassINET {
		ex.logger.DebugContext(ctx, "query refused", "name", name, "type", dns.Type(q.Qtype).String())
		return ex.reply(dns.RcodeRefused)
	}
	ex.zone = zoneName
	if q.Qtype != dns.TypeSOA {
		ex.logger.DebugContext(ctx, "query not implemented", "name", name, "type", dns.Type(q.Qtype).String())
		return ex.reply(dns.RcodeNotImplemented)
	}

	soa, fetched, err := z.cachedSOA(ctx)
	if err != nil {
		// Log the failure once per read of the backend, not once per query.
		level := slog.LevelDebug
		if fetched {
			level = slog.LevelError
		}
		ex.logger.Log(ctx, level, "reading the SOA failed", "zone", zoneName, "error", err)
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
	if z.Relay != nil {
		soa, err := z.Relay.SOA(ctx, z.Name)
		if err != nil {
			return nil, fmt.Errorf("querying the SOA of %s: %w", z.Name, err)
		}
		return soa, nil
	}
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
