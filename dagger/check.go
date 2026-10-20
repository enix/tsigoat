package main

import (
	"context"
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
