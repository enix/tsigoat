package metrics

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

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
}
