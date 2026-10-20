// Package metrics exposes the activity of tsigoat to Prometheus: responses by
// zone, key and rcode, TSIG failures, and the calls to the backends.
package metrics

import (
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"

	"github.com/enix/tsigoat/internal/backend"
	"github.com/enix/tsigoat/internal/dnsserver"
	"github.com/enix/tsigoat/internal/product"
)

const namespace = "tsigoat"

// Metrics holds the collectors of tsigoat in their own registry.
type Metrics struct {
	registry *prometheus.Registry

	responses       *prometheus.CounterVec
	responseTime    *prometheus.HistogramVec
	tsigFailures    *prometheus.CounterVec
	backendCalls    *prometheus.CounterVec
	backendCallTime *prometheus.HistogramVec
}

var _ dnsserver.Observer = (*Metrics)(nil)

// New returns the metrics of a tsigoat build, with the Go runtime and process
// collectors.
func New(info *product.Info) *Metrics {
	m := &Metrics{
		registry: prometheus.NewRegistry(),
		responses: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "dns_responses_total",
			Help: "DNS responses, by opcode, rcode, zone, and key with its TSIG algorithm. " +
				"Zone and key are empty when the request names no served zone or is not signed by a known key.",
		}, []string{"opcode", "rcode", "zone", "key", "algorithm"}),
		responseTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "dns_response_duration_seconds",
			Help:      "Time to answer DNS requests, backend calls included, by opcode.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"opcode"}),
		tsigFailures: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "tsig_failures_total",
			Help:      "Requests whose TSIG signature does not verify, by TSIG error: BADKEY, BADSIG or BADTIME.",
		}, []string{"error"}),
		backendCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: namespace,
			Name:      "backend_calls_total",
			Help: "Calls to the backends, by backend, operation (lookup or apply, relay for the updates " +
				"that a relay evaluates) and result (success or error).",
		}, []string{"backend", "operation", "result"}),
		backendCallTime: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: namespace,
			Name:      "backend_call_duration_seconds",
			Help:      "Duration of the calls to the backends, by backend and operation.",
			Buckets:   prometheus.DefBuckets,
		}, []string{"backend", "operation"}),
	}
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "build_info",
		Help:      "Always 1, labeled with the build of tsigoat.",
	}, []string{"version", "revision", "goversion"})
	buildInfo.WithLabelValues(info.Version, info.GitCommit, info.Runtime).Set(1)

	m.registry.MustRegister(
		m.responses, m.responseTime, m.tsigFailures, m.backendCalls, m.backendCallTime, buildInfo,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return m
}

// Gatherer returns the registry, for the HTTP handler.
func (m *Metrics) Gatherer() prometheus.Gatherer {
	return m.registry
}

// Observe implements dnsserver.Observer.
func (m *Metrics) Observe(a *dnsserver.Answer) {
	m.responses.WithLabelValues(a.Opcode, a.Rcode, a.Zone, a.Key, algorithmName(a.Algorithm)).Inc()
	m.responseTime.WithLabelValues(a.Opcode).Observe(a.Duration.Seconds())
	if a.TSIGError != "" {
		m.tsigFailures.WithLabelValues(a.TSIGError).Inc()
	}
}

// algorithmName returns the name of a TSIG algorithm as the configuration
// writes it: "hmac-sha256." becomes "hmac-sha256", and
// "hmac-md5.sig-alg.reg.int." becomes "hmac-md5".
func algorithmName(algorithm string) string {
	return strings.TrimSuffix(strings.TrimSuffix(algorithm, "."), ".sig-alg.reg.int")
}

// Backend wraps a backend to measure its calls: lookup and apply.
func (m *Metrics) Backend(name string, b backend.Backend) backend.Backend {
	return backend.ObservedBackend(b, func(operation string, start time.Time, err error) {
		m.observeCall(name, operation, start, err)
	})
}

// Relay wraps a relay to measure its calls: relay for the updates, lookup for
// the SOA queries.
func (m *Metrics) Relay(name string, r backend.Relay) backend.Relay {
	return backend.ObservedRelay(r, func(operation string, start time.Time, err error) {
		m.observeCall(name, operation, start, err)
	})
}

func (m *Metrics) observeCall(backendName, operation string, start time.Time, err error) {
	result := "success"
	if err != nil {
		result = "error"
	}
	m.backendCalls.WithLabelValues(backendName, operation, result).Inc()
	m.backendCallTime.WithLabelValues(backendName, operation).Observe(time.Since(start).Seconds())
}
