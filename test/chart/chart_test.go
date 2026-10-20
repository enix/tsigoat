//go:build chart

// Package chart renders the Helm chart of tsigoat, and checks the result
// against tsigoat itself.
//
// Every values file that the chart must accept, the examples of examples/helm
// and the fixtures of valid/, renders into objects whose configuration passes
// the validation of tsigoat with the files and the environment that the pod
// would see, and whose ports, probes, mounts and selectors agree. Every
// fixture of invalid/ fails to render with the messages of its .expect.txt
// file. The alerts pass the unit tests of alerts.test.yaml.
//
// `task test:helm` runs it inside Dagger, which provides helm and promtool.
package chart

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/enix/tsigoat/internal/config"
)

func TestValidValues(t *testing.T) {
	t.Parallel()

	files := valuesFiles(t, "../../examples/helm/*.values.yaml", "valid/*.yaml")
	for _, values := range files {
		t.Run(values, func(t *testing.T) {
			t.Parallel()
			checkRelease(t, render(t, values))
		})
	}
}

func TestInvalidValues(t *testing.T) {
	t.Parallel()

	for _, values := range valuesFiles(t, "invalid/*.yaml") {
		t.Run(values, func(t *testing.T) {
			t.Parallel()
			expect, err := os.ReadFile(strings.TrimSuffix(values, ".yaml") + ".expect.txt")
			if err != nil {
				t.Fatal(err)
			}
			stdout, stderr, err := helm(t, values)
			if err == nil {
				t.Fatalf("helm template accepted the values:\n%s", stdout)
			}
			for line := range strings.Lines(string(expect)) {
				line = strings.TrimSpace(line)
				if line != "" && !strings.HasPrefix(line, "#") && !strings.Contains(stderr, line) {
					t.Errorf("the error of helm template lacks %q:\n%s", line, stderr)
				}
			}
		})
	}
}

// TestAlerts runs the unit tests of the alerts with promtool, on the rules
// rendered from valid/monitoring.yaml.
func TestAlerts(t *testing.T) {
	t.Parallel()

	rules := render(t, "valid/monitoring.yaml").one(t, "PrometheusRule")
	file, err := yaml.Marshal(&rules.Spec)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tests, err := os.ReadFile("alerts.test.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{"rules.yaml": file, "alerts.test.yaml": tests} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.CommandContext(t.Context(), "promtool", "test", "rules", "alerts.test.yaml")
	command.Dir = dir
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("promtool test rules: %v\n%s", err, out)
	}
}

func valuesFiles(t *testing.T, patterns ...string) []string {
	t.Helper()
	var files []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if len(matches) == 0 {
			t.Fatalf("no values file matches %s", pattern)
		}
		files = append(files, matches...)
	}
	return files
}

// checkRelease checks a rendered release.
func checkRelease(t *testing.T, r release) {
	t.Helper()
	deployment := r.one(t, "Deployment")
	d := spec[deploymentSpec](t, deployment)
	if d.Replicas != 1 || d.Strategy.Type != "Recreate" {
		t.Errorf("%d replicas with the %s strategy, want 1 with Recreate", d.Replicas, d.Strategy.Type)
	}
	podLabels := d.Template.Metadata.Labels
	if !selects(d.Selector.MatchLabels, podLabels) {
		t.Errorf("the selector %v of the Deployment misses the pod labels %v", d.Selector.MatchLabels, podLabels)
	}
	if len(d.Template.Spec.Containers) != 1 {
		t.Fatalf("%d containers, want 1", len(d.Template.Spec.Containers))
	}
	c := &d.Template.Spec.Containers[0]
	p := newPod(t, r, &d.Template.Spec, c)

	args := flags(t, c.Args)
	checkConfig(t, p, args["--config"])
	checkListen(t, c, args["--listen"], "dns-udp", "dns-tcp")
	checkListen(t, c, args["--admin-listen"], "admin")
	for name, pr := range map[string]*probe{"liveness": c.LivenessProbe, "readiness": c.ReadinessProbe} {
		if pr == nil || pr.HTTPGet == nil {
			t.Errorf("no HTTP %s probe", name)
			continue
		}
		if containerPort(c, pr.HTTPGet.Port) == nil {
			t.Errorf("the %s probe targets port %q, which the container lacks", name, pr.HTTPGet.Port)
		}
	}
	checkServices(t, r, c, podLabels)
}

// flags parses the --flag=value arguments of serve.
func flags(t *testing.T, args []string) map[string]string {
	t.Helper()
	if len(args) == 0 || args[0] != "serve" {
		t.Fatalf("arguments %q, want serve and its flags", args)
	}
	parsed := map[string]string{}
	for _, arg := range args[1:] {
		name, value, ok := strings.Cut(arg, "=")
		if !ok {
			t.Fatalf("argument %q, want --flag=value", arg)
		}
		parsed[name] = value
	}
	return parsed
}

// checkConfig validates the configuration file of the pod, as tsigoat does.
func checkConfig(t *testing.T, p *pod, file string) {
	t.Helper()
	data, err := p.readFile(file)
	if err != nil {
		t.Fatalf("reading the configuration: %v", err)
	}
	c, _, err := config.Parse(data, config.Options{ReadFile: p.readFile, LookupEnv: p.lookupEnv})
	if err != nil {
		t.Fatalf("the configuration is invalid in the pod:\n%v\n---\n%s", err, data)
	}
	if len(c.Zones) == 0 {
		t.Error("the configuration has no zone")
	}
}

// checkListen checks that a listen address uses the container ports.
func checkListen(t *testing.T, c *container, address string, ports ...string) {
	t.Helper()
	_, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatalf("listen address %q: %v", address, err)
	}
	number, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("listen address %q: %v", address, err)
	}
	for _, name := range ports {
		if p := containerPort(c, name); p == nil || p.ContainerPort != number {
			t.Errorf("tsigoat listens on %s, which container port %s does not expose", address, name)
		}
	}
}

// containerPort returns a port of the container, by name or number.
func containerPort(c *container, ref string) *port {
	for i := range c.Ports {
		if c.Ports[i].Name == ref || strconv.Itoa(c.Ports[i].ContainerPort) == ref {
			return &c.Ports[i]
		}
	}
	return nil
}

// checkServices checks that the DNS and administration Services reach the
// pod, and that the ServiceMonitor only scrapes the administration one.
func checkServices(t *testing.T, r release, c *container, podLabels map[string]string) {
	t.Helper()
	byComponent := map[string]*object{}
	for _, o := range r["Service"] {
		byComponent[o.Metadata.Labels["app.kubernetes.io/component"]] = o
		s := spec[serviceSpec](t, o)
		if !selects(s.Selector, podLabels) {
			t.Errorf("Service %s does not select the pod", o.Metadata.Name)
		}
		for _, sp := range s.Ports {
			if cp := containerPort(c, sp.TargetPort); cp == nil || cp.Protocol != sp.Protocol {
				t.Errorf("port %s of Service %s targets %s %s, which the container lacks",
					sp.Name, o.Metadata.Name, sp.Protocol, sp.TargetPort)
			}
		}
	}
	dns, admin := byComponent["dns"], byComponent["admin"]
	if dns == nil || admin == nil || len(byComponent) != 2 {
		t.Fatalf("Services by component %v, want dns and admin", byComponent)
	}
	if s := spec[serviceSpec](t, admin); s.Type != "ClusterIP" {
		t.Errorf("the administration Service is of type %s: it would expose an unauthenticated server", s.Type)
	}

	for _, o := range r["ServiceMonitor"] {
		s := spec[serviceMonitorSpec](t, o)
		if !selects(s.Selector.MatchLabels, admin.Metadata.Labels) || selects(s.Selector.MatchLabels, dns.Metadata.Labels) {
			t.Errorf("ServiceMonitor %s does not select the administration Service alone", o.Metadata.Name)
		}
		for _, e := range s.Endpoints {
			if e.Port != "admin" || e.Path != "/metrics" {
				t.Errorf("ServiceMonitor %s scrapes %s%s, want admin/metrics", o.Metadata.Name, e.Port, e.Path)
			}
		}
	}
}
