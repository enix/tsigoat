package main

import (
	"context"

	"dagger/tsigoat/internal/dagger"
)

// LintGo runs golangci-lint with the configuration of the repository.
func (m *Tsigoat) LintGo(ctx context.Context) (string, error) {
	return golangciBase(m.Source).
		WithExec([]string{"golangci-lint", "run", "./..."}).
		Stdout(ctx)
}

// LintMarkdown runs markdownlint-cli2 on the hand-written Markdown files.
// Globs and ignores live in .markdownlint-cli2.jsonc.
func (m *Tsigoat) LintMarkdown(ctx context.Context) (string, error) {
	return dag.Container().
		From(markdownlintImage).
		WithWorkdir("/src").
		WithDirectory("/src", m.Source).
		WithExec(
			[]string{"**/*.md"},
			dagger.ContainerWithExecOpts{UseEntrypoint: true},
		).
		Stdout(ctx)
}

// LintActions checks the GitHub workflows with actionlint, then audits them
// for security issues with zizmor.
func (m *Tsigoat) LintActions(ctx context.Context) (string, error) {
	github := m.Source.Directory(".github")

	// actionlint locates the project root through its .git directory; an
	// empty one is enough and keeps the history out of the container.
	actionlint, err := dag.Container().
		From(actionlintImage).
		WithWorkdir("/src").
		WithDirectory("/src/.git", dag.Directory()).
		WithDirectory("/src/.github", github).
		WithExec([]string{"actionlint", "-color"}).
		Stdout(ctx)
	if err != nil {
		return actionlint, err
	}

	zizmor, err := dag.Container().
		From(zizmorImage).
		WithWorkdir("/src").
		WithDirectory("/src/.github", github).
		WithExec(
			[]string{"--offline", "--no-progress", "--config", ".github/zizmor.yml", ".github"},
			dagger.ContainerWithExecOpts{UseEntrypoint: true},
		).
		Stdout(ctx)
	return actionlint + zizmor, err
}

// LintDockerfile runs hadolint on the image definitions.
func (m *Tsigoat) LintDockerfile(ctx context.Context) (string, error) {
	return dag.Container().
		From(hadolintImage).
		WithWorkdir("/src").
		WithDirectory("/src/build", m.Source.Directory("build")).
		WithExec([]string{"hadolint", "build/Dockerfile.scratch", "build/Dockerfile.busybox"}).
		Stdout(ctx)
}

// LintRenovate validates renovate.json5 against the Renovate schema.
func (m *Tsigoat) LintRenovate(ctx context.Context) (string, error) {
	return dag.Container().
		From(renovateImage).
		WithWorkdir("/src").
		WithFile("/src/renovate.json5", m.Source.File("renovate.json5")).
		WithExec([]string{"renovate-config-validator", "--strict"}).
		Stdout(ctx)
}

// LintManifests validates the example Kubernetes manifests against the
// schemas of Kubernetes, and of cert-manager from the CRDs catalog.
func (m *Tsigoat) LintManifests(ctx context.Context) (string, error) {
	return dag.Container().
		From(kubeconformImage).
		WithWorkdir("/src").
		WithDirectory("/src", m.Source.Directory("examples/kubernetes")).
		WithExec([]string{
			"/kubeconform", "-strict", "-summary",
			// Not Kubernetes resources: the kustomization and the tsigoat
			// configuration.
			"-ignore-filename-pattern", `(kustomization|config)\.yaml$`,
			"-schema-location", "default",
			"-schema-location", "https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json",
			".",
		}).
		Stdout(ctx)
}
