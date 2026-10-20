// Package powerdns is a backend that applies the updates through the HTTP
// API of the PowerDNS Authoritative Server.
//
// Records travel in presentation format, which is the content format of the
// API, so that every type known to both miekg/dns and PowerDNS works without
// type-specific code. An update is a single PATCH request, which PowerDNS
// applies in one transaction.
package powerdns

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
)

const (
	// DefaultTimeout bounds every call to the API when Options set none.
	DefaultTimeout = 5 * time.Second
	// maxResponseSize bounds the responses read from the API.
	maxResponseSize = 16 << 20
)

// Options configure the backend.
type Options struct {
	// URL is the base URL of the API, such as http://pdns:8081.
	URL string
	// ServerID is the server of the API, "localhost" by default.
	ServerID string
	APIKey   string
	// Timeout bounds every call to the API; DefaultTimeout when zero.
	Timeout time.Duration
	// CAFile is a PEM bundle trusted for the certificate of the API, on top
	// of the system roots.
	CAFile string
}

// Backend is a PowerDNS backend. It is safe for concurrent use.
type Backend struct {
	// server is the URL of the API server, ending with the server ID.
	server  string
	apiKey  string
	timeout time.Duration
	client  *http.Client

	// disabled holds the disabled records that the last lookup of a name
	// found, by zone and name, then by type. PowerDNS replaces whole RRsets,
	// and tsigoat does not see disabled records: Apply puts them back into
	// the RRsets it replaces. Only the RRsets with disabled records have an
	// entry.
	disabledMu sync.Mutex
	disabled   map[string]map[string][]record
}

var _ backend.Backend = (*Backend)(nil)

// APIError is an error response of the API.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("PowerDNS API: HTTP %d", e.Status)
	}
	return fmt.Sprintf("PowerDNS API: HTTP %d: %s", e.Status, e.Message)
}

// New returns a PowerDNS backend.
func New(options *Options) (*Backend, error) {
	base, err := url.Parse(strings.TrimRight(options.URL, "/"))
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, fmt.Errorf("invalid PowerDNS URL %q", options.URL)
	}
	serverID := options.ServerID
	if serverID == "" {
		serverID = "localhost"
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("unexpected type of http.DefaultTransport")
	}
	transport = transport.Clone()
	if options.CAFile != "" {
		roots, err := loadRoots(options.CAFile)
		if err != nil {
			return nil, err
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
	}

	return &Backend{
		server:   base.String() + "/api/v1/servers/" + url.PathEscape(serverID),
		apiKey:   options.APIKey,
		timeout:  timeout,
		disabled: map[string]map[string][]record{},
		client: &http.Client{
			Transport: transport,
			// A redirect turns a PATCH into a GET, which would succeed without
			// applying anything, and hands the API key to another server:
			// redirects are errors.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}, nil
}

// loadRoots returns the system roots plus the certificates of a PEM file.
func loadRoots(path string) (*x509.CertPool, error) {
	data, err := os.ReadFile(path) //nolint:gosec // the operator chooses the CA file
	if err != nil {
		return nil, fmt.Errorf("reading the PowerDNS CA file: %w", err)
	}
	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if !roots.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("no certificate found in the PowerDNS CA file %s", path)
	}
	return roots, nil
}

// rrset is an RRset as the API represents it.
type rrset struct {
	Name string `json:"name"`
	Type string `json:"type"`
	// TTL is absent from deletions, but a TTL of zero is a TTL.
	TTL        *uint32  `json:"ttl,omitempty"`
	ChangeType string   `json:"changetype,omitempty"`
	Records    []record `json:"records"`
}

type record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

// Lookup implements backend.Backend. Disabled records are left out, as
// PowerDNS does not serve them.
func (b *Backend) Lookup(ctx context.Context, zone, name string) ([]backend.RRset, error) {
	name = dns.CanonicalName(name)
	query := url.Values{"rrsets": {"true"}, "rrset_name": {name}}
	var content struct {
		RRsets []rrset `json:"rrsets"`
	}
	if err := b.do(ctx, http.MethodGet, zonePath(zone)+"?"+query.Encode(), nil, &content); err != nil {
		return nil, err
	}

	var sets []backend.RRset
	disabled := map[string][]record{}
	for i := range content.RRsets {
		set := &content.RRsets[i]
		// Versions that ignore rrset_name return the whole zone.
		if dns.CanonicalName(set.Name) != name {
			continue
		}
		converted, err := fromAPI(set)
		if err != nil {
			return nil, fmt.Errorf("reading RRset %s %s of zone %s: %w", set.Name, set.Type, zone, err)
		}
		if len(converted.Records) > 0 {
			sets = append(sets, converted)
		}
		for _, r := range set.Records {
			if r.Disabled {
				disabled[typeName(converted.Type)] = append(disabled[typeName(converted.Type)], r)
			}
		}
	}
	b.keepDisabled(zone, name, disabled)
	return sets, nil
}

// keepDisabled records the disabled records of a name.
func (b *Backend) keepDisabled(zone, name string, disabled map[string][]record) {
	key := dns.CanonicalName(zone) + " " + name
	b.disabledMu.Lock()
	defer b.disabledMu.Unlock()
	if len(disabled) == 0 {
		delete(b.disabled, key)
		return
	}
	b.disabled[key] = disabled
}

// withDisabled adds to an RRset to replace the disabled records that the last
// lookup of its name found, but those that the RRset enables again.
func (b *Backend) withDisabled(zone string, set *rrset) {
	b.disabledMu.Lock()
	kept := b.disabled[dns.CanonicalName(zone)+" "+set.Name][set.Type]
	b.disabledMu.Unlock()
	for _, candidate := range kept {
		enabled := slices.ContainsFunc(set.Records, func(r record) bool {
			return !r.Disabled && sameContent(set.Name, set.Type, r.Content, candidate.Content)
		})
		if !enabled {
			set.Records = append(set.Records, candidate)
		}
	}
}

// Apply implements backend.Backend with a single PATCH request.
//
// PowerDNS refuses content that it would write differently, telling how it
// would. When that form is the same RDATA, Apply sends the PATCH again with
// it: a refused PATCH applies nothing.
func (b *Backend) Apply(ctx context.Context, zone string, changes []backend.Change) error {
	if len(changes) == 0 {
		return nil
	}
	body := struct {
		RRsets []rrset `json:"rrsets"`
	}{RRsets: make([]rrset, 0, len(changes))}
	records := 0
	for _, change := range changes {
		set, err := toAPI(change)
		if err != nil {
			return fmt.Errorf("%s: %w", change, err)
		}
		if change.Op == backend.Replace {
			b.withDisabled(zone, &set)
		}
		body.RRsets = append(body.RRsets, set)
		records += len(set.Records)
	}
	for attempt := 0; ; attempt++ {
		err := b.do(ctx, http.MethodPatch, zonePath(zone), body, nil)
		if err == nil || attempt == records || !reformat(err, body.RRsets) {
			return err
		}
	}
}

// do calls the API, and decodes the response into out when not nil.
func (b *Backend) do(ctx context.Context, method, path string, in, out any) error {
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()

	var payload io.Reader
	if in != nil {
		data, err := json.Marshal(in)
		if err != nil {
			return fmt.Errorf("encoding the request: %w", err)
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, b.server+path, payload)
	if err != nil {
		return fmt.Errorf("building the request: %w", err)
	}
	req.Header.Set("X-API-Key", b.apiKey)
	req.Header.Set("Accept", "application/json")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("PowerDNS API: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := io.LimitReader(resp.Body, maxResponseSize)

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		apiErr := &APIError{Status: resp.StatusCode, Message: errorMessage(body)}
		if location := resp.Header.Get("Location"); location != "" {
			apiErr.Message = "redirected to " + location + ": set the URL of the backend to the final address"
		}
		if resp.StatusCode == http.StatusNotFound {
			return fmt.Errorf("%w: %w", backend.ErrZoneNotFound, apiErr)
		}
		return apiErr
	}
	if out == nil {
		return nil
	}
	if err := json.NewDecoder(body).Decode(out); err != nil {
		return fmt.Errorf("decoding the response of the PowerDNS API: %w", err)
	}
	return nil
}

// errorMessage extracts the message of an error response.
func errorMessage(body io.Reader) string {
	data, err := io.ReadAll(io.LimitReader(body, 4096))
	if err != nil {
		return ""
	}
	var parsed struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(data, &parsed) == nil && parsed.Error != "" {
		return parsed.Error
	}
	return strings.TrimSpace(string(data))
}

// zonePath returns the path of a zone under the server URL.
func zonePath(zone string) string {
	return "/zones/" + url.PathEscape(zoneID(zone))
}

// zoneID returns the identifier of a zone in the API, which escapes the
// characters other than letters, digits, dots and hyphens as =XX, like
// apiZoneNameToId in PowerDNS.
func zoneID(zone string) string {
	name := dns.Fqdn(zone)
	if name == "." {
		return "=2E"
	}
	var id strings.Builder
	for i := range len(name) {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '.', c == '-':
			id.WriteByte(c)
		default:
			fmt.Fprintf(&id, "=%02X", c)
		}
	}
	return id.String()
}
