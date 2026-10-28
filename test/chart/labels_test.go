//go:build chart

package chart

import (
	"maps"
	"testing"
)

// TestLabelPrecedence checks that the labels of the chart win over those of
// the values, since its selectors rely on them, and that the labels of an
// object win over extraLabels.
func TestLabelPrecedence(t *testing.T) {
	t.Parallel()
	r := render(t, "valid/labels.yaml")
	chart := map[string]string{
		"app.kubernetes.io/name":       "tsigoat",
		"app.kubernetes.io/instance":   "tsigoat",
		"app.kubernetes.io/managed-by": "Helm",
	}
	components := map[string]string{"dns": "", "admin": "", "": ""}
	for kind, objects := range r {
		for name, o := range objects {
			labels := o.Metadata.Labels
			for key, want := range chart {
				if labels[key] != want {
					t.Errorf("%s %s: %s = %q, want %q", kind, name, key, labels[key], want)
				}
			}
			if _, ok := components[labels["app.kubernetes.io/component"]]; !ok {
				t.Errorf("%s %s: component %q, which the values gave", kind, name, labels["app.kubernetes.io/component"])
			}
			if labels["helm.sh/chart"] == "other" || labels["app.kubernetes.io/version"] == "other" {
				t.Errorf("%s %s: labels %v, which the values override", kind, name, labels)
			}
		}
	}

	for _, c := range []struct {
		kind, component string
		want            map[string]string
	}{
		{kind: "Service", component: "dns", want: map[string]string{"tier": "edge", "team": "dns"}},
		{kind: "Service", component: "admin", want: map[string]string{"tier": "base", "team": "dns"}},
		{kind: "ServiceMonitor", want: map[string]string{"release": "prometheus", "tier": "base"}},
		{kind: "PrometheusRule", want: map[string]string{"tier": "rules", "team": "dns"}},
		{kind: "ConfigMap", want: map[string]string{"tier": "base", "team": "dns"}},
	} {
		for name, o := range r[c.kind] {
			if o.Metadata.Labels["app.kubernetes.io/component"] != c.component {
				continue
			}
			got := map[string]string{}
			for key := range c.want {
				got[key] = o.Metadata.Labels[key]
			}
			if !maps.Equal(got, c.want) {
				t.Errorf("%s %s: labels %v, want %v", c.kind, name, got, c.want)
			}
		}
	}

	pod := spec[deploymentSpec](t, r.one(t, "Deployment")).Template.Metadata.Labels
	if pod["app.kubernetes.io/instance"] != "tsigoat" || pod["team"] != "pods" {
		t.Errorf("labels of the pod %v, want its selector labels and podLabels", pod)
	}
}
