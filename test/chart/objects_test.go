//go:build chart

package chart

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os/exec"
	"slices"
	"testing"

	"go.yaml.in/yaml/v3"
)

// chartDir holds the chart, relative to this package.
const chartDir = "../../chart"

// Release name and namespace of every rendering.
const (
	releaseName      = "tsigoat"
	releaseNamespace = "tsigoat"
)

// The subset of the Kubernetes objects that the tests read.
type (
	metadata struct {
		Name      string            `yaml:"name"`
		Namespace string            `yaml:"namespace"`
		Labels    map[string]string `yaml:"labels"`
	}

	object struct {
		Kind     string            `yaml:"kind"`
		Metadata metadata          `yaml:"metadata"`
		Data     map[string]string `yaml:"data"`
		Spec     yaml.Node         `yaml:"spec"`
	}

	deploymentSpec struct {
		Replicas int `yaml:"replicas"`
		Strategy struct {
			Type          string         `yaml:"type"`
			RollingUpdate map[string]any `yaml:"rollingUpdate"`
		} `yaml:"strategy"`
		Selector struct {
			MatchLabels map[string]string `yaml:"matchLabels"`
		} `yaml:"selector"`
		Template struct {
			Metadata metadata `yaml:"metadata"`
			Spec     podSpec  `yaml:"spec"`
		} `yaml:"template"`
	}

	podSpec struct {
		Containers []container `yaml:"containers"`
		Volumes    []volume    `yaml:"volumes"`
	}

	container struct {
		Name           string        `yaml:"name"`
		Args           []string      `yaml:"args"`
		Ports          []port        `yaml:"ports"`
		Env            []envVar      `yaml:"env"`
		VolumeMounts   []volumeMount `yaml:"volumeMounts"`
		LivenessProbe  *probe        `yaml:"livenessProbe"`
		ReadinessProbe *probe        `yaml:"readinessProbe"`
	}

	port struct {
		Name          string `yaml:"name"`
		ContainerPort int    `yaml:"containerPort"`
		Protocol      string `yaml:"protocol"`
	}

	envVar struct {
		Name      string `yaml:"name"`
		Value     string `yaml:"value"`
		ValueFrom any    `yaml:"valueFrom"`
	}

	volumeMount struct {
		Name      string `yaml:"name"`
		MountPath string `yaml:"mountPath"`
	}

	volume struct {
		Name      string `yaml:"name"`
		ConfigMap *struct {
			Name string `yaml:"name"`
		} `yaml:"configMap"`
		Secret *struct {
			SecretName string `yaml:"secretName"`
		} `yaml:"secret"`
	}

	probe struct {
		HTTPGet *struct {
			Path string `yaml:"path"`
			Port string `yaml:"port"`
		} `yaml:"httpGet"`
	}

	serviceSpec struct {
		Type     string            `yaml:"type"`
		Selector map[string]string `yaml:"selector"`
		Ports    []struct {
			Name       string `yaml:"name"`
			Port       int    `yaml:"port"`
			TargetPort string `yaml:"targetPort"`
			Protocol   string `yaml:"protocol"`
		} `yaml:"ports"`
	}

	serviceMonitorSpec struct {
		Selector struct {
			MatchLabels map[string]string `yaml:"matchLabels"`
		} `yaml:"selector"`
		Endpoints []struct {
			Port string `yaml:"port"`
			Path string `yaml:"path"`
		} `yaml:"endpoints"`
	}
)

// release holds the objects of a rendered release, by kind and name.
type release map[string]map[string]*object

// one returns the only object of a kind, failing the test unless there is
// exactly one.
func (r release) one(t *testing.T, kind string) *object {
	t.Helper()
	objects := slices.Collect(maps.Values(r[kind]))
	if len(objects) != 1 {
		t.Fatalf("%d objects of kind %s, want 1", len(objects), kind)
	}
	return objects[0]
}

// spec decodes the spec of an object.
func spec[T any](t *testing.T, o *object) *T {
	t.Helper()
	var s T
	if err := o.Spec.Decode(&s); err != nil {
		t.Fatalf("decoding the spec of %s %s: %v", o.Kind, o.Metadata.Name, err)
	}
	return &s
}

// helm runs helm template with a values file, returning its output and its
// error output.
func helm(t *testing.T, values string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errOut bytes.Buffer
	command := exec.CommandContext(t.Context(), "helm", "template", releaseName, chartDir,
		"--namespace", releaseNamespace, "--values", values)
	command.Stdout, command.Stderr = &out, &errOut
	err = command.Run()
	return out.String(), errOut.String(), err
}

// render renders the chart with a values file, and decodes the objects.
func render(t *testing.T, values string) release {
	t.Helper()
	stdout, stderr, err := helm(t, values)
	if err != nil {
		t.Fatalf("helm template: %v\n%s", err, stderr)
	}
	objects, err := decode(stdout)
	if err != nil {
		t.Fatal(err)
	}
	return objects
}

func decode(manifests string) (release, error) {
	objects := release{}
	decoder := yaml.NewDecoder(bytes.NewBufferString(manifests))
	for {
		var o object
		err := decoder.Decode(&o)
		if errors.Is(err, io.EOF) {
			return objects, nil
		}
		if err != nil {
			return nil, fmt.Errorf("decoding the rendered objects: %w", err)
		}
		if o.Kind == "" {
			continue
		}
		if objects[o.Kind] == nil {
			objects[o.Kind] = map[string]*object{}
		}
		if _, duplicate := objects[o.Kind][o.Metadata.Name]; duplicate {
			return nil, fmt.Errorf("two objects %s %s", o.Kind, o.Metadata.Name)
		}
		objects[o.Kind][o.Metadata.Name] = &o
	}
}

// selects tells whether every label of a selector is among labels.
func selects(selector, labels map[string]string) bool {
	if len(selector) == 0 {
		return false
	}
	for name, value := range selector {
		if labels[name] != value {
			return false
		}
	}
	return true
}
