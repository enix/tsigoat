//go:build chart

package chart

import (
	"reflect"
	"testing"
)

// dnsService returns the spec and the labels of the DNS Service of a release.
func dnsService(t *testing.T, r release) (fields map[string]any, labels map[string]string) {
	t.Helper()
	for _, o := range r["Service"] {
		if o.Metadata.Labels["app.kubernetes.io/component"] == "dns" {
			return *spec[map[string]any](t, o), o.Metadata.Labels
		}
	}
	t.Fatal("the release holds no DNS Service")
	return nil, nil
}

// TestServiceSettings checks that the settings of the DNS Service reach its
// spec where Kubernetes takes them: the node ports and the fields of a load
// balancer with their type alone, and externalTrafficPolicy with external IPs
// too.
func TestServiceSettings(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		label  string
		values string
		args   []string
		want   map[string]any
		absent []string
	}{
		{
			label:  "external IPs",
			values: "valid/external-ips.yaml",
			want: map[string]any{
				"type": "ClusterIP", "clusterIP": "10.96.0.53", "externalIPs": []any{"192.0.2.53"},
				"externalTrafficPolicy": "Local", "ipFamilyPolicy": "PreferDualStack",
				"ipFamilies": []any{"IPv4", "IPv6"}, "internalTrafficPolicy": "Local",
				"trafficDistribution": "PreferSameZone",
			},
			absent: []string{"loadBalancerIP", "allocateLoadBalancerNodePorts", "healthCheckNodePort"},
		},
		{
			label:  "load balancer",
			values: "valid/exposed.yaml",
			want: map[string]any{
				"type": "LoadBalancer", "externalTrafficPolicy": "Local", "healthCheckNodePort": 30054,
				"loadBalancerClass": "example.test/lb", "loadBalancerIP": "192.0.2.10",
				"allocateLoadBalancerNodePorts": false,
			},
		},
		{
			label:  "health check node port without the Local policy",
			values: "valid/exposed.yaml",
			args:   []string{"--set", "service.externalTrafficPolicy=Cluster"},
			want:   map[string]any{"externalTrafficPolicy": "Cluster"},
			absent: []string{"healthCheckNodePort"},
		},
		{
			label:  "settings of a load balancer on a ClusterIP Service",
			values: "valid/exposed.yaml",
			args:   []string{"--set", "service.type=ClusterIP"},
			want:   map[string]any{"type": "ClusterIP"},
			absent: []string{
				"externalTrafficPolicy", "healthCheckNodePort", "loadBalancerClass", "loadBalancerIP",
				"loadBalancerSourceRanges", "allocateLoadBalancerNodePorts",
			},
		},
	} {
		t.Run(c.label, func(t *testing.T) {
			t.Parallel()
			fields, _ := dnsService(t, render(t, c.values, c.args...))
			for field, want := range c.want {
				if got := fields[field]; !reflect.DeepEqual(got, want) {
					t.Errorf("%s = %#v, want %#v", field, got, want)
				}
			}
			for _, field := range c.absent {
				if got, ok := fields[field]; ok {
					t.Errorf("%s = %#v, want none", field, got)
				}
			}
			if fields["type"] == "ClusterIP" {
				ports, _ := fields["ports"].([]any)
				for _, port := range ports {
					p, _ := port.(map[string]any)
					if nodePort, ok := p["nodePort"]; ok {
						t.Errorf("a ClusterIP Service has the node port %v", nodePort)
					}
				}
			}
		})
	}
}

// TestServiceLabels checks that service.extraLabels label the DNS Service
// alone, and that a label of the chart wins over the same one there: the
// selector of the ServiceMonitor tells the two Services apart by it.
func TestServiceLabels(t *testing.T) {
	t.Parallel()
	r := render(t, "valid/external-ips.yaml")
	_, labels := dnsService(t, r)
	if labels["announce.example.test/bgp"] != "true" {
		t.Errorf("labels of the DNS Service %v, want those of service.extraLabels", labels)
	}
	if labels["app.kubernetes.io/component"] != "dns" {
		t.Errorf("the DNS Service has the component %q, want dns", labels["app.kubernetes.io/component"])
	}
	for _, o := range r["Service"] {
		if o.Metadata.Labels["app.kubernetes.io/component"] != "dns" && o.Metadata.Labels["announce.example.test/bgp"] != "" {
			t.Errorf("service.extraLabels label the Service %s too", o.Metadata.Name)
		}
	}
}
