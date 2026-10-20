// Package scaleway is a backend that applies the updates through the Domains
// and DNS API of Scaleway, with the secret key of an API key.
//
// Scaleway stores records one by one, each with an identifier. tsigoat reads
// the records of a name, computes which records to create, delete or retime,
// and sends them in a single PATCH request, which Scaleway applies as a
// whole. Scaleway manages the SOA and the NS records of the apex, which
// tsigoat shows but never changes.
package scaleway

import (
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
	// DefaultURL is the base URL of the API.
	DefaultURL = "https://api.scaleway.com"
	// DefaultTimeout bounds every call to the API when Options set none.
	DefaultTimeout = 5 * time.Second
	// provider names Scaleway in messages.
	provider = "Scaleway"
	// pageSize is the number of records of a page of a listing.
	pageSize = 1000
)

// Options configure the backend.
type Options struct {
	// URL is the base URL of the API; DefaultURL when empty.
	URL string
	// SecretKey is the secret key of the API key that authenticates the
	// requests.
	SecretKey string
	// Timeout bounds every call to the API; DefaultTimeout when zero.
	Timeout time.Duration
	// UserAgent identifies tsigoat.
	UserAgent string
}

// Backend is a Scaleway backend. It is safe for concurrent use.
type Backend struct {
	api    *hosted.API
	limits *hosted.Limits
}

var (
	_ backend.Backend  = (*Backend)(nil)
	_ backend.TTLFloor = (*Backend)(nil)
)

// New returns a Scaleway backend.
func New(options *Options) (*Backend, error) {
	base := strings.TrimRight(options.URL, "/")
	if base == "" {
		base = DefaultURL
	}
	if u, err := url.Parse(base); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("invalid Scaleway API URL %q", options.URL)
	}
	if options.SecretKey == "" {
		return nil, errors.New("missing Scaleway secret key")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	client, err := httpclient.New(&httpclient.Options{})
	if err != nil {
		return nil, fmt.Errorf("configuring the client of the Scaleway API: %w", err)
	}
	key := options.SecretKey
	return &Backend{
		api: &hosted.API{
			Provider:  provider,
			Base:      base,
			Client:    client,
			Timeout:   timeout,
			UserAgent: options.UserAgent,
			Authorize: func(req *http.Request, _ []byte) error {
				req.Header.Set("X-Auth-Token", key)
				return nil
			},
			Describe: describe,
		},
		limits: newLimits(),
	}, nil
}

// describe extracts the message and the type of an error response.
func describe(_ http.Header, body []byte) (message, code string) {
	var r struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Details []struct {
			ArgumentName string `json:"argument_name"`
			Reason       string `json:"reason"`
			HelpMessage  string `json:"help_message"`
		} `json:"details"`
	}
	if json.Unmarshal(body, &r) != nil || r.Message == "" {
		return "", ""
	}
	var b strings.Builder
	b.WriteString(r.Message)
	for _, d := range r.Details {
		fmt.Fprintf(&b, "; %s: %s %s", d.ArgumentName, d.Reason, d.HelpMessage)
	}
	return strings.TrimSpace(b.String()), r.Type
}

// MinTTL implements backend.TTLFloor.
func (*Backend) MinTTL() uint32 {
	return minTTL
}

// recordsPath returns the path of the records of a zone in the API.
func recordsPath(zone string) string {
	return "/domain/v2beta1/dns-zones/" + url.PathEscape(strings.TrimSuffix(zone, ".")) + "/records"
}

// notFound turns the errors of a missing zone into backend.ErrZoneNotFound:
// Scaleway answers 403 "domain not found", or 404.
func notFound(zone string, err error) error {
	status := hosted.StatusOf(err)
	if status == http.StatusNotFound || (status == http.StatusForbidden && strings.Contains(err.Error(), "not found")) {
		return fmt.Errorf("%s: %w: %w", zone, backend.ErrZoneNotFound, err)
	}
	return err
}

// records returns the records of a name, with their identifiers, reading
// every page of the listing. The API filters the names loosely, and not at
// all for the apex, whose name is empty: the caller keeps the records of the
// exact name.
func (b *Backend) records(ctx context.Context, zone, name string) ([]hosted.Record, error) {
	relative := hosted.Relative(name, zone)
	var records []hosted.Record
	for page, read := 1, 0; ; page++ {
		query := url.Values{"page": {strconv.Itoa(page)}, "page_size": {strconv.Itoa(pageSize)}}
		if relative != "" {
			query.Set("name", relative)
		}
		var response struct {
			TotalCount int         `json:"total_count"`
			Records    []APIRecord `json:"records"`
		}
		if err := b.api.Do(ctx, http.MethodGet, recordsPath(zone)+"?"+query.Encode(), nil, &response); err != nil {
			return nil, notFound(zone, err)
		}
		for i := range response.Records {
			r := &response.Records[i]
			if dns.CanonicalName(name) != ownerName(r.Name, zone) {
				continue
			}
			held, err := FromAPI(r, zone)
			if err != nil {
				return nil, fmt.Errorf("reading record %s of zone %s: %w", r.ID, zone, err)
			}
			if held.RR != nil {
				records = append(records, held)
			}
		}
		read += len(response.Records)
		if len(response.Records) == 0 || read >= response.TotalCount {
			return records, nil
		}
	}
}

// Lookup implements backend.Backend.
func (b *Backend) Lookup(ctx context.Context, zone, name string) ([]backend.RRset, error) {
	zone, name = dns.CanonicalName(zone), dns.CanonicalName(name)
	records, err := b.records(ctx, zone, name)
	if err != nil {
		return nil, err
	}
	sets := hosted.RRsets(records)
	if name == zone {
		sets = append(sets, soaRRset(zone, sets))
	}
	return sets, nil
}

// The SOA that tsigoat shows for the zones: Scaleway serves its own, with
// these timers, and a serial that its API does not tell.
const (
	soaTTL     = 3600
	soaRefresh = 86400
	soaRetry   = 7200
	soaExpire  = 604800
	soaMinimum = 3600
)

// soaRRset returns the SOA that tsigoat makes up for a zone: its primary is
// the first name server of the apex.
func soaRRset(zone string, sets []backend.RRset) backend.RRset {
	primary := "ns0.dom.scw.cloud."
	for _, set := range sets {
		if set.Type == dns.TypeNS && len(set.Records) > 0 {
			if ns, ok := set.Records[0].(*dns.NS); ok {
				primary = ns.Ns
			}
		}
	}
	soa := &dns.SOA{
		Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: soaTTL},
		Ns:  primary, Mbox: "hostmaster." + zone, Serial: 1,
		Refresh: soaRefresh, Retry: soaRetry, Expire: soaExpire, Minttl: soaMinimum,
	}
	return backend.RRset{Name: zone, Type: dns.TypeSOA, TTL: soaTTL, Records: []dns.RR{soa}}
}
