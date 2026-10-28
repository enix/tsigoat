//go:build chart

package chart

import (
	"slices"
	"testing"
)

// TestListenHost checks that an IPv6 listen host gets the brackets that the
// listen addresses of tsigoat want, and that other hosts stay as they are.
func TestListenHost(t *testing.T) {
	t.Parallel()
	for host, want := range map[string]string{
		"::":           "[::]",
		"2001:db8::53": "[2001:db8::53]",
		"[::]":         "[::]",
		"0.0.0.0":      "0.0.0.0",
	} {
		t.Run(host, func(t *testing.T) {
			t.Parallel()
			d := spec[deploymentSpec](t, render(t, "valid/minimal.yaml", "--set-string", "listenHost="+host).one(t, "Deployment"))
			args := d.Template.Spec.Containers[0].Args
			for _, arg := range []string{"--listen=" + want + ":5353", "--admin-listen=" + want + ":9153"} {
				if !slices.Contains(args, arg) {
					t.Errorf("arguments %v, want %s", args, arg)
				}
			}
		})
	}
}
