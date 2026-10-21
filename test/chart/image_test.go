//go:build chart

package chart

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestImage checks the reference to the image: the release writes the
// digest of each of its tags into image.digests, and the chart pulls those
// tags by digest, on any registry, and the other tags by tag.
func TestImage(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join(chartDir, "Chart.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var chart struct {
		AppVersion string `yaml:"appVersion"`
	}
	if err := yaml.Unmarshal(data, &chart); err != nil {
		t.Fatal(err)
	}
	version := chart.AppVersion
	scratch, busybox, other := "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("c", 64)
	digests := fmt.Sprintf(`image.digests={%q: %q, %q: %q}`, version, scratch, version+"-busybox", busybox)

	for _, c := range []struct {
		name string
		args []string
		want string
	}{
		{"without digests", nil, "ghcr.io/enix/tsigoat:" + version},
		{"release", []string{"--set-json", digests}, "ghcr.io/enix/tsigoat:" + version + "@" + scratch},
		{"busybox", []string{"--set-json", digests, "--set", "image.tagSuffix=-busybox"}, "ghcr.io/enix/tsigoat:" + version + "-busybox@" + busybox},
		{"other registry", []string{"--set-json", digests, "--set", "global.imageRegistry=quay.io"}, "quay.io/enix/tsigoat:" + version + "@" + scratch},
		{"other tag", []string{"--set-json", digests, "--set", "image.tag=9.9.9"}, "ghcr.io/enix/tsigoat:9.9.9"},
		{"explicit digest", []string{"--set-json", digests, "--set", "image.digest=" + other}, "ghcr.io/enix/tsigoat@" + other},
		{"not pinned", []string{"--set-json", digests, "--set", "image.pinDigest=false"}, "ghcr.io/enix/tsigoat:" + version},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			d := spec[deploymentSpec](t, render(t, "valid/minimal.yaml", c.args...).one(t, "Deployment"))
			if got := d.Template.Spec.Containers[0].Image; got != c.want {
				t.Errorf("image %q, want %q", got, c.want)
			}
		})
	}
}
