package app_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/memory"
	"github.com/enix/tsigoat/internal/backend/webhook"
	"github.com/enix/tsigoat/internal/update"
	"github.com/enix/tsigoat/internal/zone"
	"github.com/enix/tsigoat/test/scenario"
)

const (
	// webhookParent holds the zones of the scenarios run through a webhook.
	webhookParent = "webhook.test."
	webhookSecret = "secret of the webhook" // gitleaks:allow (fixture)
)

// engineEndpoint is a webhook endpoint that applies the operations it
// receives to the in-memory backend, with the update engine of tsigoat.
type engineEndpoint struct {
	backend *memory.Backend
	// mu serializes the updates, as tsigoat already does.
	mu sync.Mutex
}

func (e *engineEndpoint) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	timestamp := r.Header.Get(webhook.TimestampHeader)
	if r.Header.Get(webhook.SignatureHeader) != webhook.Sign([]byte(webhookSecret), timestamp, body) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	var request webhook.Request
	if err := json.Unmarshal(body, &request); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	updates := make([]dns.RR, 0, len(request.Operations))
	for _, op := range request.Operations {
		rr, err := record(&op)
		if err == nil {
			rr, err = asReceived(rr)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		updates = append(updates, rr)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	view := zone.NewView(e.backend, request.Zone)
	if err := update.Apply(r.Context(), view, &update.Request{Zone: request.Zone, Class: dns.ClassINET, Updates: updates}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if changes := view.Changes(); len(changes) > 0 {
		if err := e.backend.Apply(r.Context(), request.Zone, changes); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

// record turns an operation back into a record of the update section.
func record(op *webhook.Operation) (dns.RR, error) {
	switch {
	case op.Op == "add" && op.TTL != nil:
		return dns.NewRR(fmt.Sprintf("%s %d IN %s %s", op.Name, *op.TTL, op.Type, op.RData))
	case op.Op == "delete" && op.RData != "":
		return dns.NewRR(fmt.Sprintf("%s 0 NONE %s %s", op.Name, op.Type, op.RData))
	case op.Op == "delete":
		rrtype := dns.TypeANY
		if op.Type != "" {
			parsed, err := typeCode(op.Type)
			if err != nil {
				return nil, err
			}
			rrtype = parsed
		}
		return &dns.ANY{Hdr: dns.RR_Header{Name: op.Name, Rrtype: rrtype, Class: dns.ClassANY}}, nil
	default:
		return nil, fmt.Errorf("unknown operation %+v", op)
	}
}

// asReceived returns a record as the server hands it to the engine: decoded
// from a DNS message, whose RDATA may differ in form from the same RDATA
// parsed from text, such as hexadecimal digits in another case, then
// normalized.
func asReceived(rr dns.RR) (dns.RR, error) {
	decoded, err := backend.Canonical(rr)
	if err != nil {
		return nil, fmt.Errorf("decoding %s: %w", rr, err)
	}
	return decoded, nil
}

func typeCode(name string) (uint16, error) {
	if code, ok := dns.StringToType[name]; ok {
		return code, nil
	}
	code, err := strconv.ParseUint(strings.TrimPrefix(name, "TYPE"), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("unknown type %q", name)
	}
	return uint16(code), nil
}

// webhookLimit tells why a scenario cannot run through a webhook, or "".
func webhookLimit(t *testing.T, s *scenario.Scenario, zoneName string) string {
	t.Helper()
	for i := range s.Requests {
		messages, err := s.Requests[i].Messages(zoneName)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range messages {
			if len(m.Answer) > 0 {
				return "the webhook backend refuses prerequisites"
			}
			for _, rr := range m.Ns {
				if h := rr.Header(); h.Class == dns.ClassANY && h.Rrtype == dns.TypeANY && dns.CanonicalName(h.Name) == zoneName {
					return "the webhook backend refuses to delete every RRset of the apex"
				}
			}
		}
	}
	return ""
}

// TestScenariosThroughWebhook runs the scenarios through tsigoat posting the
// updates to a webhook, which applies them with the update engine: the JSON
// of the requests must carry every record faithfully.
func TestScenariosThroughWebhook(t *testing.T) {
	t.Parallel()

	scenarios, err := scenario.All()
	if err != nil {
		t.Fatal(err)
	}
	b := memory.New()
	endpoint := httptest.NewServer(&engineEndpoint{backend: b})
	t.Cleanup(endpoint.Close)
	c := scenarioConfig(t, scenarios, webhookParent, scenario.Webhook{URL: endpoint.URL, Secret: webhookSecret})
	target := &memoryTarget{backend: b, addr: serve(t, c, nil)}
	for _, s := range scenarios {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			if reason := webhookLimit(t, &s, s.ZoneName(webhookParent)); reason != "" {
				t.Skip(reason)
			}
			scenario.Run(t, target, &s, webhookParent)
		})
	}
}
