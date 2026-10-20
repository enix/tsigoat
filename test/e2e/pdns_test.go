//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// pdnsTarget is tsigoat in front of PowerDNS, for the scenario runner.
type pdnsTarget struct {
	api  *powerDNS
	addr string
}

func (p *pdnsTarget) Addr() string {
	return p.addr
}

func (p *pdnsTarget) ResetZone(ctx context.Context, zone string, records []dns.RR) error {
	if err := p.api.resetZone(ctx, zone); err != nil {
		return err
	}
	return p.api.addRecords(ctx, zone, records)
}

func (p *pdnsTarget) Records(ctx context.Context, zone string) ([]dns.RR, error) {
	return p.api.records(ctx, zone)
}

// powerDNS is a minimal client of the PowerDNS HTTP API, used to prepare the
// zones of the scenarios and to read their content back.
type powerDNS struct {
	base   string
	apiKey string
	client *http.Client
}

type rrset struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	TTL        *uint32  `json:"ttl,omitempty"`
	ChangeType string   `json:"changetype,omitempty"`
	Records    []record `json:"records"`
}

type record struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

func newPowerDNS(url, apiKey string) *powerDNS {
	return &powerDNS{
		base:   strings.TrimRight(url, "/") + "/api/v1/servers/localhost",
		apiKey: apiKey,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// resetZone deletes the zone if it exists, then creates it empty: an SOA and
// one apex NS record.
func (p *powerDNS) resetZone(ctx context.Context, zone string) error {
	status, err := p.do(ctx, http.MethodDelete, "/zones/"+zone, nil, nil)
	if err != nil && status != http.StatusNotFound && status != http.StatusUnprocessableEntity {
		return err
	}
	_, err = p.do(ctx, http.MethodPost, "/zones", map[string]any{
		"name":        zone,
		"kind":        "Native",
		"nameservers": []string{"ns1." + zone},
	}, nil)
	return err
}

// addRecords replaces the RRsets of the given records.
func (p *powerDNS) addRecords(ctx context.Context, zone string, records []dns.RR) error {
	if len(records) == 0 {
		return nil
	}
	type key struct{ name, rrtype string }
	sets := map[key]*rrset{}
	var order []key
	for _, rr := range records {
		h := rr.Header()
		k := key{name: dns.CanonicalName(h.Name), rrtype: dns.TypeToString[h.Rrtype]}
		set, ok := sets[k]
		if !ok {
			set = &rrset{Name: k.name, Type: k.rrtype, TTL: new(h.Ttl), ChangeType: "REPLACE"}
			sets[k] = set
			order = append(order, k)
		}
		set.Records = append(set.Records, record{Content: rdata(rr)})
	}
	body := make([]*rrset, 0, len(order))
	for _, k := range order {
		body = append(body, sets[k])
	}
	_, err := p.do(ctx, http.MethodPatch, "/zones/"+zone, map[string]any{"rrsets": body}, nil)
	return err
}

// records returns the records of the zone, but its SOA.
func (p *powerDNS) records(ctx context.Context, zone string) ([]dns.RR, error) {
	var content struct {
		RRsets []rrset `json:"rrsets"`
	}
	if _, err := p.do(ctx, http.MethodGet, "/zones/"+zone, nil, &content); err != nil {
		return nil, err
	}
	var records []dns.RR
	for _, set := range content.RRsets {
		if set.Type == "SOA" {
			continue
		}
		for _, r := range set.Records {
			var ttl uint32
			if set.TTL != nil {
				ttl = *set.TTL
			}
			rr, err := dns.NewRR(fmt.Sprintf("%s %d IN %s %s", set.Name, ttl, set.Type, r.Content))
			if err == nil && rr == nil {
				err = errors.New("no record")
			}
			if err != nil {
				return nil, fmt.Errorf("parsing %s %s %q: %w", set.Name, set.Type, r.Content, err)
			}
			records = append(records, rr)
		}
	}
	return records, nil
}

func (p *powerDNS) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var payload io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, fmt.Errorf("encoding %s %s: %w", method, path, err)
		}
		payload = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.base+path, payload)
	if err != nil {
		return 0, fmt.Errorf("building %s %s: %w", method, path, err)
	}
	req.Header.Set("X-API-Key", p.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := p.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode >= http.StatusMultipleChoices {
		detail, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, bytes.TrimSpace(detail))
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, fmt.Errorf("decoding %s %s: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// rdata returns the RDATA of a record in presentation format, which is the
// content format of the PowerDNS API.
func rdata(rr dns.RR) string {
	return strings.TrimPrefix(rr.String(), rr.Header().String())
}
