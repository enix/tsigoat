package main

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"dagger/tsigoat/internal/dagger"
)

// CheckFmt fails when a Go file is not formatted according to the
// formatters configured in .golangci.yml.
func (m *Tsigoat) CheckFmt(ctx context.Context) (string, error) {
	return golangciBase(m.Source).
		WithExec([]string{"golangci-lint", "fmt", "--diff", "./..."}).
		Stdout(ctx)
}

// CheckToolchain fails when the golang image of the pipelines and the toolchain
// directive of go.mod name different Go versions: the tests would run with
// another compiler and standard library than the releases.
func (m *Tsigoat) CheckToolchain(ctx context.Context) (string, error) {
	goMod, err := m.Source.File("go.mod").Contents(ctx)
	if err != nil {
		return "", err
	}
	toolchain := regexp.MustCompile(`(?m)^toolchain go(\S+)$`).FindStringSubmatch(goMod)
	image := regexp.MustCompile(`^golang:([0-9.]+)-`).FindStringSubmatch(golangImage)
	switch {
	case toolchain == nil:
		return "", errors.New("go.mod has no toolchain directive")
	case image == nil:
		return "", fmt.Errorf("no Go version in the golang image %s", golangImage)
	case toolchain[1] != image[1]:
		return "", fmt.Errorf("go.mod names toolchain go%s, the golang image of dagger/base.go Go %s: move them together", toolchain[1], image[1])
	}
	return fmt.Sprintf("go.mod and the golang image both name Go %s\n", image[1]), nil
}

// CheckTidy fails when go.mod or go.sum is not tidy.
func (m *Tsigoat) CheckTidy(ctx context.Context) (string, error) {
	return goBase(m.Source).
		WithExec([]string{"go", "mod", "tidy", "-diff"}).
		Stdout(ctx)
}

// CheckDaggerFmt fails when a Go file of this Dagger module is not formatted
// with gofmt. The module stays out of the source that the other checks see.
func (m *Tsigoat) CheckDaggerFmt(ctx context.Context) (string, error) {
	return dag.Container().
		From(golangImage).
		WithDirectory("/module", dag.CurrentModule().Source(), dagger.ContainerWithDirectoryOpts{
			Include: []string{"*.go"},
			Exclude: []string{"dagger.gen.go"},
		}).
		WithWorkdir("/module").
		WithExec([]string{"sh", "-euc", `
unformatted=$(gofmt -l .)
if [ -n "$unformatted" ]; then
  echo "not formatted with gofmt:"; echo "$unformatted"; exit 1
fi
echo "every file of the Dagger module is formatted"
`}).
		Stdout(ctx)
}
