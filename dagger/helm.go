package main

import (
	"context"
	"strings"

	"dagger/tsigoat/internal/dagger"
)

// chartValues lists the values files that the chart must accept: the
// examples, then the fixtures of the chart test.
const chartValues = "examples/helm/*.values.yaml test/chart/valid/*.yaml"

// HelmDocs generates the files of the chart that derive from values.yaml:
// README.md, from README.md.gotmpl and the `# --` comments of the values, and
// values.schema.json, from the values and their `# @schema` annotations, with
// the schema of config from the types of the configuration file.
// `task doc:helm` exports them into chart/.
func (m *Tsigoat) HelmDocs() *dagger.Directory {
	chart := m.Source.Directory("chart")
	readme := dag.Container().
		From(helmDocsImage).
		WithWorkdir("/src").
		WithDirectory("/src/chart", chart).
		WithExec([]string{
			"helm-docs", "--chart-search-root=chart",
			"--sort-values-order=file", "--skip-version-footer",
		}).
		File("/src/chart/README.md")
	// The image runs as an unprivileged user, who cannot write into the
	// mounted chart; helm-schema would swallow the error.
	schema := dag.Container().
		From(helmSchemaImage).
		WithUser("root").
		WithWorkdir("/src").
		WithDirectory("/src/chart", chart).
		WithExec(
			[]string{
				"--chart-search-root=chart",
				// The README already describes the values.
				"--skip-auto-generation=title,description",
				"--append-newline",
			},
			dagger.ContainerWithExecOpts{UseEntrypoint: true},
		).
		File("/src/chart/values.schema.json")
	// The schema of config comes from the types that decode the
	// configuration file: it refuses the fields that tsigoat does not know.
	configSchema := goBase(m.Source).
		WithExec([]string{"go", "run", "./internal/config/printschema"},
			dagger.ContainerWithExecOpts{RedirectStdout: "/tmp/config.schema.json"}).
		File("/tmp/config.schema.json")
	schema = dag.Container().
		From(alpineImage).
		WithExec([]string{"apk", "add", "--no-cache", "jq"}).
		WithFile("/tmp/values.schema.json", schema).
		WithFile("/tmp/config.schema.json", configSchema).
		WithExec([]string{"sh", "-euc",
			`jq --slurpfile config /tmp/config.schema.json '.properties.config += $config[0]' /tmp/values.schema.json > /tmp/merged.json`}).
		File("/tmp/merged.json")
	return dag.Directory().
		WithFile("README.md", readme).
		WithFile("values.schema.json", schema)
}

// CheckHelmDocs fails when chart/README.md or chart/values.schema.json
// differs from what `task doc:helm` generates.
func (m *Tsigoat) CheckHelmDocs(ctx context.Context) (string, error) {
	return dag.Container().
		From(alpineImage).
		WithDirectory("/committed", m.Source.Directory("chart"), dagger.ContainerWithDirectoryOpts{
			Include: []string{"README.md", "values.schema.json"},
		}).
		WithDirectory("/generated", m.HelmDocs()).
		WithExec([]string{"sh", "-euc", `
if ! diff -ru /committed /generated; then
  echo "the generated files of the chart are stale: run task doc:helm"; exit 1
fi
echo "the generated files of the chart are up to date"
`}).
		Stdout(ctx)
}

// LintHelm runs `helm lint --strict` on the chart with every example and
// valid fixture: the chart requires a configuration, so that its default
// values alone do not render.
func (m *Tsigoat) LintHelm(ctx context.Context) (string, error) {
	return helmBase(m.Source).
		WithExec([]string{"sh", "-euc", `
for values in ` + chartValues + `; do
  echo "== $values"
  helm lint --strict chart --namespace tsigoat --values "$values"
done
`}).
		Stdout(ctx)
}

// TestHelm checks the chart: the Go test of test/chart renders it with every
// example and fixture, validates the rendered configuration with tsigoat's
// own rules, checks that ports, probes, mounts and selectors agree, and runs
// the unit tests of the alerts with promtool; kubeconform then validates the
// rendered objects against the schemas of Kubernetes and of the Prometheus
// operator.
func (m *Tsigoat) TestHelm(ctx context.Context) (string, error) {
	test, err := goBase(m.Source).
		WithFile("/usr/local/bin/helm", dag.Container().From(helmImage).File("/usr/bin/helm")).
		WithFile("/usr/local/bin/promtool", dag.Container().From(prometheusImage).File("/bin/promtool")).
		WithExec([]string{"go", "test", "-tags", "chart", "-count=1", "./test/chart/"}).
		Stdout(ctx)
	if err != nil {
		return test, err
	}

	rendered := helmBase(m.Source).
		WithExec([]string{"sh", "-euc", `
mkdir -p /rendered
for values in ` + chartValues + `; do
  name=$(basename "$values" .yaml)
  helm template tsigoat chart --namespace tsigoat --values "$values" > "/rendered/$name.yaml"
done
`}).
		Directory("/rendered")
	schemas, err := dag.Container().
		From(kubeconformImage).
		WithWorkdir("/rendered").
		WithDirectory("/rendered", rendered).
		WithExec([]string{
			"/kubeconform", "-strict", "-summary",
			"-schema-location", "default",
			"-schema-location", crdCatalog,
			".",
		}).
		Stdout(ctx)
	return strings.Join([]string{test, schemas}, "\n"), err
}

// crdCatalog locates the schemas of custom resources, such as those of
// cert-manager and of the Prometheus operator.
const crdCatalog = "https://raw.githubusercontent.com/datreeio/CRDs-catalog/main/{{.Group}}/{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"

// helmBase returns a Helm container with the chart and the values files that
// it must accept.
func helmBase(source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(helmImage).
		WithWorkdir("/src").
		WithDirectory("/src/chart", source.Directory("chart")).
		WithDirectory("/src/examples/helm", source.Directory("examples/helm")).
		WithDirectory("/src/test/chart", source.Directory("test/chart"))
}
