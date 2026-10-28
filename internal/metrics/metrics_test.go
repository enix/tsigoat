package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/backend/memory"
	"github.com/enix/tsigoat/internal/dnsserver"
	"github.com/enix/tsigoat/internal/product"
)

func newMetrics(t *testing.T) *Metrics {
	t.Helper()
	info := product.Info{Version: "1.2.3", GitCommit: "abc", Runtime: "go1.26"}
	return New(&info)
}

func TestObserve(t *testing.T) {
	t.Parallel()
	m := newMetrics(t)

	before := time.Now()
	m.Observe(&dnsserver.Answer{
		Opcode: "UPDATE", Rcode: "NOERROR", Zone: "example.test.", Key: "key.",
		Algorithm: "hmac-md5.sig-alg.reg.int.", Duration: 3 * time.Millisecond,
	})
	m.Observe(&dnsserver.Answer{Opcode: "UPDATE", Rcode: "NOTAUTH", TSIGError: "BADSIG"})

	if got := testutil.ToFloat64(m.responses.WithLabelValues("UPDATE", "NOERROR", "example.test.", "key.", "hmac-md5")); got != 1 {
		t.Errorf("responses of key. = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.tsigFailures.WithLabelValues("BADSIG")); got != 1 {
		t.Errorf("BADSIG failures = %v, want 1", got)
	}
	if count := testutil.CollectAndCount(m.responseTime); count != 1 {
		t.Errorf("%d response time series, want 1", count)
	}
	// The time of the last use of key., which the unsigned request leaves
	// alone.
	if count := testutil.CollectAndCount(m.keyLastUse); count != 1 {
		t.Errorf("%d last use series, want the one of key.", count)
	}
	lastUse := testutil.ToFloat64(m.keyLastUse.WithLabelValues("key.", "hmac-md5"))
	if lastUse < float64(before.Unix()) || lastUse > float64(time.Now().Unix()+1) {
		t.Errorf("last use of key. = %v, want the time of its request", lastUse)
	}
	want := `
# HELP tsigoat_build_info Always 1, labeled with the build of tsigoat.
# TYPE tsigoat_build_info gauge
tsigoat_build_info{goversion="go1.26",revision="abc",version="1.2.3"} 1
`
	if err := testutil.GatherAndCompare(m.Gatherer(), strings.NewReader(want), "tsigoat_build_info"); err != nil {
		t.Error(err)
	}
}

func TestAlgorithmName(t *testing.T) {
	t.Parallel()
	for algorithm, want := range map[string]string{
		"hmac-sha256.":              "hmac-sha256",
		"hmac-md5.sig-alg.reg.int.": "hmac-md5",
		"":                          "",
	} {
		if got := algorithmName(algorithm); got != want {
			t.Errorf("algorithmName(%q) = %q, want %q", algorithm, got, want)
		}
	}
}

func TestBackend(t *testing.T) {
	t.Parallel()
	m := newMetrics(t)
	b := m.Backend("pdns", memory.New())
	// Every series exists from the start, at zero.
	for _, result := range []string{"success", "error", "indeterminate"} {
		if n := testutil.CollectAndCount(m.backendCalls, "tsigoat_backend_calls_total"); n != 6 {
			t.Fatalf("%d series of backend calls, want 6", n)
		}
		if got := testutil.ToFloat64(m.backendCalls.WithLabelValues("pdns", "apply", result)); got != 0 {
			t.Errorf("apply calls with result %s = %v, want 0", result, got)
		}
	}
	if got := testutil.ToFloat64(m.lastIndeterminate.WithLabelValues("pdns")); got != 0 {
		t.Errorf("time of the last unknown outcome = %v, want 0", got)
	}

	if _, err := b.Lookup(context.Background(), "missing.test.", "missing.test."); !errors.Is(err, backend.ErrZoneNotFound) {
		t.Errorf("Lookup() error %v, want the error of the backend", err)
	}
	if err := b.Apply(context.Background(), "missing.test.", []backend.Change{{Op: backend.Delete, RRset: backend.RRset{Name: "missing.test."}}}); err == nil {
		t.Error("Apply() succeeded on a missing zone")
	}
	for _, operation := range []string{"lookup", "apply"} {
		if got := testutil.ToFloat64(m.backendCalls.WithLabelValues("pdns", operation, "error")); got != 1 {
			t.Errorf("failed %s calls = %v, want 1", operation, got)
		}
	}

	// An update that the backend turns down is no failure of the backend.
	rejecting := memory.New()
	rejecting.FailApply(&backend.RejectionError{Rcode: dns.RcodeRefused, Reason: "rejected"})
	b = m.Backend("provider", rejecting)
	if err := b.Apply(context.Background(), "example.test.", nil); err == nil {
		t.Error("Apply() succeeded, want the rejection of the backend")
	}
	if got := testutil.ToFloat64(m.backendCalls.WithLabelValues("provider", "apply", "success")); got != 1 {
		t.Errorf("turned down apply calls with result success = %v, want 1", got)
	}

	// An update whose outcome is unknown counts apart.
	uncertain := memory.New()
	uncertain.FailApply(backend.Indeterminate(errors.New("timeout")))
	b = m.Backend("uncertain", uncertain)
	if err := b.Apply(context.Background(), "example.test.", nil); !backend.IsIndeterminate(err) {
		t.Errorf("Apply() = %v, want the indeterminate error of the backend", err)
	}
	if got := testutil.ToFloat64(m.backendCalls.WithLabelValues("uncertain", "apply", "indeterminate")); got != 1 {
		t.Errorf("apply calls with result indeterminate = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.lastIndeterminate.WithLabelValues("uncertain")); time.Since(time.Unix(int64(got), 0)) > time.Minute {
		t.Errorf("time of the last unknown outcome = %v, want now", got)
	}
}

// stubRelay turns updates down, with NXRRSET or with a rejection for those
// of rejected., and fails the SOA queries and the checks.
type stubRelay struct{}

func (stubRelay) Update(_ context.Context, zone, _ string, _, _ []dns.RR) (int, error) {
	if zone == "rejected." {
		return 0, &backend.RejectionError{Rcode: dns.RcodeRefused, Reason: "rejected"}
	}
	return dns.RcodeNXRrset, nil
}

func (stubRelay) SOA(context.Context, string) (dns.RR, error) {
	return nil, errors.New("unreachable")
}

func (stubRelay) Check(context.Context, string) error {
	return errors.New("unreachable")
}

func TestRelay(t *testing.T) {
	t.Parallel()
	m := newMetrics(t)
	r := m.Relay("bind", stubRelay{})

	if rcode, err := r.Update(t.Context(), "example.test.", "", nil, nil); rcode != dns.RcodeNXRrset || err != nil {
		t.Errorf("Update() = %d, %v, want the answer of the relay", rcode, err)
	}
	if _, err := r.Update(t.Context(), "rejected.", "", nil, nil); err == nil {
		t.Error("Update() succeeded, want the rejection of the relay")
	}
	if _, err := r.SOA(t.Context(), "example.test."); err == nil {
		t.Error("SOA() succeeded, want the error of the relay")
	}
	if err := r.Check(t.Context(), "example.test."); err == nil {
		t.Error("Check() succeeded, want the error of the relay")
	}
	for _, call := range []struct {
		operation, result string
		count             float64
	}{{"relay", "success", 2}, {"lookup", "error", 1}, {"check", "error", 1}} {
		if got := testutil.ToFloat64(m.backendCalls.WithLabelValues("bind", call.operation, call.result)); got != call.count {
			t.Errorf("%s calls with result %s = %v, want %v", call.operation, call.result, got, call.count)
		}
	}
}
