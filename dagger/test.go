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
