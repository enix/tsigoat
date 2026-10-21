// Package webhook relays DNS updates to an HTTP endpoint, as JSON: a script or
// a service of the operator, which applies them with whatever the provider of
// the zone offers, such as a command line tool.
//
// An update is one POST request, which a 2xx response applies; any other
// response fails it, as does a timeout or a transport error. The request
// lists the operations of the update section, in order: additions and
// deletions, with the records in presentation format. tsigoat leaves out the
// deletions that RFC 2136 ignores whatever the state of the zone, turns down
// the updates that the endpoint could not evaluate without reading the zone,
// and sends the updates of a zone one at a time, while the endpoint answers
// within the timeout. A request that fails once it left whole, as on a
// timeout, leaves the outcome of its update unknown.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/httpclient"
)

// Version is the version of the format of the requests.
const Version = 1

// The operations of an update.
const (
	OpAdd    = "add"
	OpDelete = "delete"
)

// The headers of the signature of a request.
const (
	// TimestampHeader holds the time of the request, in seconds since the
	// Unix epoch.
	TimestampHeader = "X-Tsigoat-Timestamp"
	// SignatureHeader holds "sha256=" and the hexadecimal HMAC-SHA256, with
	// the secret, of the timestamp, a period and the body.
	SignatureHeader = "X-Tsigoat-Signature"
)

const (
	// DefaultTimeout bounds every request when Options set none.
	DefaultTimeout = 5 * time.Second
	// soaTTL is the TTL of the SOA that tsigoat makes up for the zones.
	soaTTL = 300
	// maxErrorBody bounds the part of an error response that tsigoat logs.
	maxErrorBody = 256
)

// Request is the body of a request: an update of a zone.
type Request struct {
	Version int `json:"version"`
	// ID identifies the request: 128 random bits in hexadecimal, unique to
	// each request, so that an endpoint can recognize a request that comes
	// twice, a replay.
	ID string `json:"id"`
	// Zone is the canonical name of the zone.
	Zone string `json:"zone"`
	// Key is the canonical name of the key that signed the update, "" when
	// unsigned.
	Key string `json:"key"`
	// Operations apply in order. The check of the endpoint sends none.
	Operations []Operation `json:"operations"`
}

// Operation is an operation of an update.
type Operation struct {
	// Op is OpAdd or OpDelete.
	Op string `json:"op"`
	// Name is the canonical owner name.
	Name string `json:"name"`
	// Type is the record type, such as TXT. A deletion without a type
	// deletes every record of the name.
	Type string `json:"type,omitempty"`
	// TTL is the TTL of the record to add.
	TTL *uint32 `json:"ttl,omitempty"`
	// RData is the RDATA of the record to add, or of the one record to
	// delete, in presentation format. A deletion without RDATA deletes every
	// record of the type.
	RData string `json:"rdata,omitempty"`
}

// Options configure a relay.
type Options struct {
	// URL is the address of the endpoint.
	URL string
	// Timeout bounds every request, from the connection to the end of the
	// response; DefaultTimeout when zero.
	Timeout time.Duration
	// CAFile, InsecureSkipVerify and FollowRedirects configure the client,
	// see httpclient.Options.
	CAFile             string
	InsecureSkipVerify bool
	FollowRedirects    bool
	// SignatureSecret signs the requests, when set.
	SignatureSecret string
	// Username and Password authenticate the requests with HTTP basic
	// authentication, when Username is set.
	Username, Password string
	// BearerToken authenticates the requests with a bearer token, when set.
	BearerToken string
	// Header holds the headers of every request.
	Header http.Header
	// UserAgent identifies tsigoat.
	UserAgent string
}

// Relay posts the updates of its zones to an endpoint.
type Relay struct {
	url string
	// redactedURL names the endpoint in errors, without its password.
	redactedURL string
	client      *http.Client
	signature   []byte
	username    string
	password    string
	bearer      string
	header      http.Header

	// locks holds a lock per zone, a channel so that waiting for it honours
	// the deadline of the request.
	locksMu sync.Mutex
	locks   map[string]chan struct{}
}

var _ backend.Relay = (*Relay)(nil)

// New returns a relay to an endpoint.
func New(o *Options) (*Relay, error) {
	u, err := url.Parse(o.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid webhook URL %q", o.URL)
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client, err := httpclient.New(&httpclient.Options{
		CAFile:             o.CAFile,
		InsecureSkipVerify: o.InsecureSkipVerify,
		FollowRedirects:    o.FollowRedirects,
		Timeout:            timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("configuring the client of the webhook: %w", err)
	}
	header := o.Header.Clone()
	if header == nil {
		header = http.Header{}
	}
	header.Set("Content-Type", "application/json")
	if o.UserAgent != "" {
		header.Set("User-Agent", o.UserAgent)
	}
	r := &Relay{
		url:         u.String(),
		redactedURL: u.Redacted(),
		client:      client,
		username:    o.Username,
		password:    o.Password,
		bearer:      o.BearerToken,
		header:      header,
		locks:       map[string]chan struct{}{},
	}
	if o.SignatureSecret != "" {
		r.signature = []byte(o.SignatureSecret)
	}
	return r, nil
}

// Update implements backend.Relay.
func (r *Relay) Update(ctx context.Context, zone, key string, prerequisites, updates []dns.RR) (int, error) {
	if len(prerequisites) > 0 {
		return 0, &backend.RejectionError{
			Rcode:  dns.RcodeRefused,
			Reason: "the webhook backend does not evaluate prerequisites",
		}
	}
	operations, err := Operations(zone, updates)
	if err != nil {
		return 0, err
	}
	if len(operations) == 0 {
		return dns.RcodeSuccess, nil
	}
	err = r.post(ctx, &Request{Version: Version, ID: newID(), Zone: zone, Key: key, Operations: operations})
	if uncertain, ok := errors.AsType[*uncertainError](err); ok {
		return 0, backend.Indeterminate(uncertain.err)
	}
	if err != nil {
		return 0, err
	}
	return dns.RcodeSuccess, nil
}

// SOA implements backend.Relay. The endpoint holds no SOA: the SOA queries of
// a zone, which clients send to find the zone of a name, get one that tsigoat
// makes up.
func (*Relay) SOA(_ context.Context, zone string) (dns.RR, error) {
	return &dns.SOA{
		Hdr:     dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTTL},
		Ns:      zone,
		Mbox:    "hostmaster." + zone,
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  soaTTL,
	}, nil
}

// Check implements backend.Relay: it posts an update without operations,
// which the endpoint must accept without changing anything.
func (r *Relay) Check(ctx context.Context, zone string) error {
	err := r.post(ctx, &Request{Version: Version, ID: newID(), Zone: zone, Operations: []Operation{}})
	if uncertain, ok := errors.AsType[*uncertainError](err); ok {
		// A check changes nothing, whatever its outcome.
		return uncertain.err
	}
	return err
}

// newID returns a new identifier of a request: 128 random bits, in
// hexadecimal.
func newID() string {
	var id [16]byte
	// crypto/rand never fails.
	_, _ = rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

// uncertainError is a failure of a request that may have reached the
// endpoint, which may have applied it: a timeout or a broken connection once
// the request left whole, or a gateway that answers for an endpoint that
// broke off or took too long.
type uncertainError struct {
	err error
}

func (e *uncertainError) Error() string {
	return e.err.Error()
}

func (e *uncertainError) Unwrap() error {
	return e.err
}

// Operations returns the operations of the update section of an update of
// zone, without the deletions that RFC 2136 ignores whatever the state of the
// zone: of the SOA, and of the NS RRset of the apex. It turns down the
// deletion of every RRset of the apex, which spares the SOA and the NS
// records: the endpoint could not tell them apart.
func Operations(zone string, updates []dns.RR) ([]Operation, error) {
	operations := make([]Operation, 0, len(updates))
	for _, rr := range updates {
		h := rr.Header()
		name := dns.CanonicalName(h.Name)
		rrtype := dns.Type(h.Rrtype).String()
		switch {
		case h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY:
			if name == zone {
				return nil, &backend.RejectionError{
					Rcode:  dns.RcodeRefused,
					Reason: "the webhook backend does not delete every RRset of the apex: delete them by type",
				}
			}
			operations = append(operations, Operation{Op: OpDelete, Name: name})
		case h.Class == dns.ClassANY:
			if h.Rrtype == dns.TypeSOA || (h.Rrtype == dns.TypeNS && name == zone) {
				continue
			}
			operations = append(operations, Operation{Op: OpDelete, Name: name, Type: rrtype})
		case h.Class == dns.ClassNONE:
			if h.Rrtype == dns.TypeSOA {
				continue
			}
			operations = append(operations, Operation{Op: OpDelete, Name: name, Type: rrtype, RData: backend.RData(rr)})
		default:
			ttl := h.Ttl
			operations = append(operations, Operation{Op: OpAdd, Name: name, Type: rrtype, TTL: &ttl, RData: backend.RData(rr)})
		}
	}
	return operations, nil
}

// post sends a request, once the previous request of its zone is over, and
// fails unless the status of the response is a success, which is the answer
// of the endpoint, whatever the body. A failure that leaves the outcome
// unknown is an *uncertainError.
func (r *Relay) post(ctx context.Context, request *Request) error {
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("encoding the request: %w", err)
	}
	unlock, err := r.lock(ctx, request.Zone)
	if err != nil {
		return err
	}
	defer unlock()

	// sent tells whether the request left whole: the endpoint may apply it
	// whatever happens next.
	var sent atomic.Bool
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err == nil {
				sent.Store(true)
			}
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building the request: %w", err)
	}
	req.Header = r.header.Clone()
	switch {
	case r.username != "":
		req.SetBasicAuth(r.username, r.password)
	case r.bearer != "":
		req.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	if r.signature != nil {
		timestamp := strconv.FormatInt(time.Now().Unix(), 10)
		req.Header.Set(TimestampHeader, timestamp)
		req.Header.Set(SignatureHeader, Sign(r.signature, timestamp, body))
	}

	// The errors of the client name the URL without its password.
	resp, err := r.client.Do(req)
	if err != nil {
		err = fmt.Errorf("posting the update: %w", err)
		if sent.Load() {
			return &uncertainError{err: err}
		}
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 == 2 {
		return nil
	}
	// The start of the body tells why, as far as it comes in time.
	excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	err = responseError(r.redactedURL, resp, excerpt)
	// A 4xx tells that the endpoint applied nothing, as a redirect does; a 5xx
	// may come once it applied part of the update, or from a gateway while
	// it applies it still.
	if resp.StatusCode/100 == 5 {
		return &uncertainError{err: err}
	}
	return err
}

// Sign returns the value of the signature header of a request.
func Sign(secret []byte, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte("."))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// responseError describes a response that is not a success.
func responseError(endpoint string, resp *http.Response, excerpt []byte) error {
	message := fmt.Sprintf("%s answered %s", endpoint, resp.Status)
	if location := resp.Header.Get("Location"); resp.StatusCode/100 == 3 && location != "" {
		message += ", redirecting to " + location +
			": set the URL to the final address, or followRedirects for a 307 or 308 redirect to the same scheme and host"
	}
	if text := strings.Join(strings.Fields(string(excerpt)), " "); text != "" {
		message += ": " + text
	}
	return errors.New(message)
}

// lock takes the lock of a zone, unless ctx ends first, and returns the
// function that releases it.
func (r *Relay) lock(ctx context.Context, zone string) (func(), error) {
	r.locksMu.Lock()
	lock, ok := r.locks[zone]
	if !ok {
		lock = make(chan struct{}, 1)
		r.locks[zone] = lock
	}
	r.locksMu.Unlock()
	select {
	case lock <- struct{}{}:
		return func() { <-lock }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("waiting for the previous update of zone %s: %w", zone, ctx.Err())
	}
}
