package main

import (
	"context"
)

// Test runs the unit tests through gotestsum, with the race detector, a
// shuffled order and a coverage profile. The race detector requires CGO,
// which pulls gcc and musl-dev on Alpine.
func (m *Tsigoat) Test(ctx context.Context) (string, error) {
	return goBase(m.Source).
		WithExec([]string{"apk", "add", "--no-cache", "gcc", "musl-dev"}).
		WithEnvVariable("CGO_ENABLED", "1").
		WithExec([]string{"go", "install", "gotest.tools/gotestsum@" + gotestsumModule}).
		WithExec([]string{
			"gotestsum",
			"--format=pkgname-and-test-fails",
			"--junitfile=/tmp/junit.xml",
			"--",
			"-race",
			"-shuffle=on",
			"-coverprofile=/tmp/coverage.out",
			"./...",
		}).
		Stdout(ctx)
}

// Fuzz runs every fuzz target of the module in turn, each for the given time.
// Targets are discovered with `go test -list`, so that new ones run without
// touching the pipeline.
func (m *Tsigoat) Fuzz(
	ctx context.Context,
	// Time given to each target, as a Go duration or a number of runs such
	// as "1000x".
	// +optional
	// +default="1m"
	fuzztime string,
) (string, error) {
	return goBase(m.Source).
		WithEnvVariable("FUZZTIME", fuzztime).
		WithExec([]string{"sh", "-euc", `
for pkg in $(go list ./...); do
  for target in $(go test -list '^Fuzz' "$pkg" | grep '^Fuzz' || true); do
    echo "== $target ($pkg)"
    go test -run '^$' -fuzz "^$target\$" -fuzztime "$FUZZTIME" "$pkg"
  done
done
`}).
		Stdout(ctx)
}
