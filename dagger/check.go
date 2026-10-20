package main

import (
	"context"

	"dagger/tsigoat/internal/dagger"
)

// CheckFmt fails when a Go file is not formatted according to the
// formatters configured in .golangci.yml.
func (m *Tsigoat) CheckFmt(ctx context.Context) (string, error) {
	return golangciBase(m.Source).
		WithExec([]string{"golangci-lint", "fmt", "--diff", "./..."}).
		Stdout(ctx)
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
