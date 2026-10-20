// Package ovh is a backend that applies the updates through the API of
// OVHcloud, with an application key or an OAuth2 service account.
//
// OVHcloud stores records one by one, each with an identifier, and its name
// servers serve a zone as it stood at its last refresh. tsigoat reads the
// records of a name, computes which records to create, delete or retime,
// applies them one request at a time, then refreshes the zone once, so that
// the name servers see the update whole. The API has no transaction, and a
// request that fails may have applied: when a request or the refresh fails,
// tsigoat reads the records again and brings them back to their content
// before the update, then publishes the zone; when that fails too, the
// outcome is unknown, and the zone may hold part of the update. OVHcloud
// manages the SOA and the NS records of the apex, which tsigoat shows but
// never changes.
package ovh

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/hosted"
	"github.com/enix/tsigoat/internal/backend/httpclient"
)

const (
	// DefaultTimeout bounds every call to the API when Options set none.
	DefaultTimeout = 5 * time.Second
	// provider names OVHcloud in messages.
	provider = "OVHcloud"
)

// Options configure the backend.
type Options struct {
	// Endpoint is the base URL of the API, such as EndpointEU.
	Endpoint string
	// ApplicationKey, ApplicationSecret and ConsumerKey sign the requests,
	// when ApplicationKey is set.
	ApplicationKey, ApplicationSecret, ConsumerKey string
	// ClientID and ClientSecret are the credentials of an OAuth2 service
	// account, when ClientID is set.
	ClientID, ClientSecret string
	// TokenURL is the OAuth2 token endpoint; the one of the endpoint of
	// OVHcloud when empty.
	TokenURL string
	// Timeout bounds every call to the API; DefaultTimeout when zero.
	Timeout time.Duration
	// RefreshDelay is the delay before the second attempt of a refresh,
	// which doubles for the next one; one second when zero.
	RefreshDelay time.Duration
	// UserAgent identifies tsigoat.
	UserAgent string
}

// Backend is an OVHcloud backend. It is safe for concurrent use.
type Backend struct {
	api    *hosted.API
	limits *hosted.Limits
	// clock tells the time of the API, for the signatures; nil with an
	// OAuth2 service account.
	clock *clock
	// refreshDelay is the delay before the second attempt of a refresh.
	refreshDelay time.Duration
}

var (
	_ backend.Backend  = (*Backend)(nil)
	_ backend.TTLFloor = (*Backend)(nil)
)

// New returns an OVHcloud backend.
func New(options *Options) (*Backend, error) {
	endpoint := strings.TrimRight(options.Endpoint, "/")
	if u, err := url.Parse(endpoint); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("invalid OVHcloud API endpoint %q", options.Endpoint)
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client, err := httpclient.New(&httpclient.Options{})
	if err != nil {
		return nil, fmt.Errorf("configuring the client of the OVHcloud API: %w", err)
	}
	b := &Backend{
		api: &hosted.API{
			Provider:  provider,
			Base:      endpoint,
			Client:    client,
			Timeout:   timeout,
			UserAgent: options.UserAgent,
			Describe:  describe,
		},
		limits:       newLimits(),
		refreshDelay: cmp.Or(options.RefreshDelay, defaultRefreshDelay),
	}

	if err := b.authenticate(options, client, timeout); err != nil {
		return nil, err
	}
	return b, nil
}

// authenticate sets how the backend authenticates its requests: with the
// signature of an application key, or the tokens of an OAuth2 service
// account.
func (b *Backend) authenticate(options *Options, client *http.Client, timeout time.Duration) error {
	switch {
	case options.ApplicationKey != "" && options.ClientID != "":
		return errors.New("set an application key or an OAuth2 service account, not both")
	case options.ApplicationKey != "":
		if options.ApplicationSecret == "" || options.ConsumerKey == "" {
			return errors.New("an application key needs its secret and a consumer key")
		}
		unsigned := *b.api
		unsigned.Authorize = func(*http.Request, []byte) error { return nil }
		b.clock = &clock{fetch: func(ctx context.Context) (time.Time, error) { return apiTime(ctx, &unsigned) }}
		s := &signer{
			applicationKey: options.ApplicationKey, applicationSecret: options.ApplicationSecret,
			consumerKey: options.ConsumerKey, clock: b.clock,
		}
		b.api.Authorize = s.authorize
	case options.ClientID != "":
		tokens := &tokenSource{
			url: options.TokenURL, clientID: options.ClientID, clientSecret: options.ClientSecret,
			client: client, timeout: timeout, userAgent: options.UserAgent,
		}
		if tokens.url == "" {
			var ok bool
			if tokens.url, ok = tokenURL(b.api.Base); !ok {
				return fmt.Errorf("OAuth2 service accounts need an endpoint of OVHcloud, not %s", b.api.Base)
			}
		}
		b.api.Authorize = tokens.authorize
	default:
		return errors.New("missing credentials: an application key or an OAuth2 service account")
	}
	return nil
}

// MinTTL implements backend.TTLFloor.
func (*Backend) MinTTL() uint32 {
	return minTTL
}

// apiTime returns the time of the API, which needs no authentication.
func apiTime(ctx context.Context, api *hosted.API) (time.Time, error) {
	var seconds int64
	if err := api.Do(ctx, http.MethodGet, "/auth/time", nil, &seconds); err != nil {
		return time.Time{}, err
	}
	return time.Unix(seconds, 0), nil
}

// describe extracts the message and the class of an error response, with the
// identifier of the query, which the support of OVHcloud asks for.
func describe(header http.Header, body []byte) (message, code string) {
	var r struct {
		Class     string `json:"class"`
		ErrorCode string `json:"errorCode"`
		Message   string `json:"message"`
		Details   *struct {
			UnauthorizedActionsByIAM any `json:"unauthorizedActionsByIAM"`
		} `json:"details"`
	}
	if json.Unmarshal(body, &r) != nil || r.Message == "" {
		return "", ""
	}
	code = r.Class
	if code == "" {
		code = r.ErrorCode
	}
	message = r.Message
	if r.Details != nil && r.Details.UnauthorizedActionsByIAM != nil {
		message += fmt.Sprintf(" (actions refused by IAM: %v)", r.Details.UnauthorizedActionsByIAM)
	}
	if query := header.Get("X-Ovh-Queryid"); query != "" {
		message += " (query " + query + ")"
	}
	return message, code
}

// do calls the API. A request turned down because its signature carries
// another time than the API goes again, once, after reading the time of the
// API again.
func (b *Backend) do(ctx context.Context, method, path string, in, out any) error {
	err := b.api.Do(ctx, method, path, in, out)
	if b.clock != nil && hosted.StatusOf(err) == http.StatusBadRequest && strings.Contains(err.Error(), "Query out of time") {
		b.clock.reset()
		err = b.api.Do(ctx, method, path, in, out)
	}
	return err
}

// zonePath returns the path of a zone in the API.
func zonePath(zone string) string {
	return "/domain/zone/" + url.PathEscape(strings.TrimSuffix(zone, "."))
}

// notFound turns the errors of a missing zone into backend.ErrZoneNotFound:
// 404, and 460 for an expired zone.
func notFound(zone string, err error) error {
	if status := hosted.StatusOf(err); status == http.StatusNotFound || status == statusExpired {
		return fmt.Errorf("%s: %w: %w", zone, backend.ErrZoneNotFound, err)
	}
	return err
}

// statusExpired is the status of the API for an expired zone.
const statusExpired = 460

// recordIDs returns the identifiers of the records of a name. The API filters
// the names with SQL LIKE, without regard to case, so that the caller keeps
// the records of the exact name.
func (b *Backend) recordIDs(ctx context.Context, zone, name string) ([]int64, error) {
	query := url.Values{"subDomain": {hosted.Relative(name, zone)}}
	var ids []int64
	if err := b.do(ctx, http.MethodGet, zonePath(zone)+"/record?"+query.Encode(), nil, &ids); err != nil {
		return nil, notFound(zone, err)
	}
	return ids, nil
}

// records returns the records of a name, with their identifiers.
func (b *Backend) records(ctx context.Context, zone, name string) ([]hosted.Record, error) {
	ids, err := b.recordIDs(ctx, zone, name)
	if err != nil {
		return nil, err
	}
	reader := &recordReader{backend: b, zone: zone, relative: hosted.Relative(name, zone)}
	records := make([]hosted.Record, 0, len(ids))
	for _, id := range ids {
		rr, readErr := reader.read(ctx, id)
		if readErr != nil {
			return nil, readErr
		}
		if rr != nil {
			records = append(records, hosted.Record{ID: strconv.FormatInt(id, 10), RR: rr})
		}
	}
	return records, nil
}

// recordReader reads the records of a name, one at a time.
type recordReader struct {
	backend  *Backend
	zone     string
	relative string
	// defaultTTL is the default TTL of the zone, once read.
	defaultTTL *uint32
}

// read reads a record of the name, nil when it does not exist anymore, or
// when it belongs to another name, which the filter of the API matched too.
func (r *recordReader) read(ctx context.Context, id int64) (dns.RR, error) {
	var record apiRecord
	if err := r.backend.do(ctx, http.MethodGet, zonePath(r.zone)+"/record/"+strconv.FormatInt(id, 10), nil, &record); err != nil {
		if hosted.StatusOf(err) == http.StatusNotFound {
			// Deleted since the listing.
			return nil, nil //nolint:nilnil // a record deleted meanwhile is no error
		}
		return nil, err
	}
	if !strings.EqualFold(record.SubDomain, r.relative) {
		return nil, nil //nolint:nilnil // the filter of the API matches other names too
	}
	if record.TTL == 0 && r.defaultTTL == nil {
		// A TTL of 0 is the default TTL of the zone.
		soa, err := r.backend.soa(ctx, r.zone)
		if err != nil {
			return nil, err
		}
		r.defaultTTL = &soa.TTL
	}
	var defaultTTL uint32
	if r.defaultTTL != nil {
		defaultTTL = *r.defaultTTL
	}
	rr, err := fromAPI(&record, r.zone, defaultTTL)
	if err != nil {
		return nil, fmt.Errorf("reading record %d of zone %s: %w", id, r.zone, err)
	}
	return rr, nil
}

// Lookup implements backend.Backend.
func (b *Backend) Lookup(ctx context.Context, zone, name string) ([]backend.RRset, error) {
	zone, name = dns.CanonicalName(zone), dns.CanonicalName(name)
	records, err := b.records(ctx, zone, name)
	if err != nil {
		return nil, err
	}
	sets := hosted.RRsets(records)
	if name != zone {
		return sets, nil
	}
	soa, err := b.soa(ctx, zone)
	if err != nil {
		return nil, err
	}
	return append(sets, backend.RRset{Name: zone, Type: dns.TypeSOA, TTL: soa.TTL, Records: []dns.RR{soa.record(zone)}}), nil
}

// apiSOA is the SOA of a zone, as the API gives it.
type apiSOA struct {
	Server      string  `json:"server"`
	Email       string  `json:"email"`
	Serial      uint32  `json:"serial"`
	Refresh     uint32  `json:"refresh"`
	Retry       *uint32 `json:"retry"`
	Expire      uint32  `json:"expire"`
	NXDomainTTL uint32  `json:"nxDomainTtl"`
	// TTL is the default TTL of the zone, which its SOA has too.
	TTL uint32 `json:"ttl"`
}

// defaultRetry is the retry interval of the SOA when the API leaves it out,
// as the zones of OVHcloud have it.
const defaultRetry = 3600

// soa reads the SOA of a zone.
func (b *Backend) soa(ctx context.Context, zone string) (*apiSOA, error) {
	var soa apiSOA
	if err := b.do(ctx, http.MethodGet, zonePath(zone)+"/soa", nil, &soa); err != nil {
		return nil, notFound(zone, err)
	}
	return &soa, nil
}

// record returns the SOA as a record.
func (s *apiSOA) record(zone string) *dns.SOA {
	retry := uint32(defaultRetry)
	if s.Retry != nil {
		retry = *s.Retry
	}
	return &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: s.TTL},
		Ns:  dns.Fqdn(strings.ToLower(s.Server)), Mbox: mailbox(s.Email), Serial: s.Serial,
		Refresh: s.Refresh, Retry: retry, Expire: s.Expire, Minttl: s.NXDomainTTL,
	}
}

// mailbox returns the RNAME of an SOA from the email address of the API, or
// from a name that is one already.
func mailbox(email string) string {
	local, domain, found := strings.Cut(email, "@")
	if !found {
		return dns.Fqdn(strings.ToLower(email))
	}
	return dns.Fqdn(strings.ReplaceAll(local, ".", `\.`) + "." + strings.ToLower(domain))
}
