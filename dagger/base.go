package main

import (
	"dagger/tsigoat/internal/dagger"
)

// Pinned image versions. Renovate's regex manager tracks the
// `<name>Image = "..."` literals and the Go install versions below.
const (
	golangImage       = "golang:1.27.2-alpine@sha256:f92b6ef800e499660581efdabdf25d9d817a9d124eaf900924f0504e7e27e12d"
	alpineImage       = "alpine:3.24.2@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6"
	markdownlintImage = "davidanson/markdownlint-cli2:v0.23.3@sha256:d5f3f3f04b2e285dcbcdcd13b4454d119e273e3c393a9dabd163dba4abad526d"
	actionlintImage   = "rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
	zizmorImage       = "ghcr.io/zizmorcore/zizmor:1.31.1@sha256:42d409dbb851d4c5d35a058cf042b828bea1e3f2884378c526eb0974780e18d9"
	hadolintImage     = "hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d"
	renovateImage     = "renovate/renovate:44.167.7@sha256:756a6b0a12154d076e90f38332f674e87ddc5bbbfeaf9ec796f80c435c5c3de5"
	trivyImage        = "aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222"
	gitleaksImage     = "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
	pdns49Image       = "powerdns/pdns-auth-49:4.9.17@sha256:b554df74bbde1afa7caedad4af9c91378be6d46d05807d089b3c7c443002e684"
	pdns50Image       = "powerdns/pdns-auth-50:5.0.7@sha256:4d6cc4fc42a28f2df7fb55f6f36d8323f96e0da66135ccdad057ca7349b223b4"
	toxiproxyImage    = "ghcr.io/shopify/toxiproxy:2.13.0@sha256:5d3dae09bc185dcc5ff6cf43abf6062a4a720aff0c4306a471e773acdcd107aa"
	kubeconformImage  = "ghcr.io/yannh/kubeconform:v0.8.0@sha256:faffaf43f95aa6425306e1ab8d6fcad72acb9049158f38e574c085ea1ec0f64e"
	helmImage         = "alpine/helm:4.3.1@sha256:e3f8d5c462d75470fbb1fce79ad5c20063657096d1f98c0fcea869e2600e2e5e"
	helmDocsImage     = "jnorwood/helm-docs:v1.14.2@sha256:7e562b49ab6b1dbc50c3da8f2dd6ffa8a5c6bba327b1c6335cc15ce29267979c"
	helmSchemaImage   = "ghcr.io/dadav/helm-schema:v0.24.0@sha256:efa1a88d082728c81eb1734a263b0ec0eb353b99f49dc199f22e2567bf0fef9f"
	prometheusImage   = "quay.io/prometheus/prometheus:v3.15.0@sha256:efd719c99d83b060d9daefdcf00360461adf279f45ef5391f8d111892118753e"
	pebbleImage       = "ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"
	legoImage         = "goacme/lego:v4.35.2@sha256:ae124a405844759b201b31efbd7a0ba302dbd16e86f2fb177c4b6db8bdc782c8"
	certbotImage      = "certbot/dns-rfc2136:v5.8.0@sha256:55d52a5de51df312cadbcce1dc105f20d639bc127699e791323c2a27db05ac1f"
	k3sImage          = "rancher/k3s:v1.37.1-k3s1@sha256:ca7f37d993d82ef0dcdcfecb2e0e2618ea541dbaffc620c8cedebe01a82acd0d"
	kubectlImage      = "alpine/k8s:1.37.1@sha256:712dc5385d1c1a3f83b747fa9e40f64d433a97f72ff42f9755ff7dd1f62846e4"
	certManagerChart  = "v1.21.2" // oci://quay.io/jetstack/charts/cert-manager
	golangciLint      = "v2.15.0" // installed via `go install`
	gotestsumModule   = "v1.13.0" // ditto
	gremlinsModule    = "v0.6.0"  // ditto
	govulncheckPath   = "latest"  // tracking latest, no Renovate pin
)

// goBase returns a Go container with go.mod/go.sum prefetched and the module
// and build caches mounted. Every Go-flavoured function starts here.
func goBase(source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(golangImage).
		WithEnvVariable("GOTOOLCHAIN", "auto").
		WithEnvVariable("CGO_ENABLED", "0").
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod")).
		WithMountedCache("/root/.cache/go-build", dag.CacheVolume("go-build")).
		WithWorkdir("/src").
		WithFile("/src/go.mod", source.File("go.mod")).
		WithFile("/src/go.sum", source.File("go.sum")).
		WithExec([]string{"go", "mod", "download"}).
		WithDirectory("/src", source)
}

// golangciBase stages golangci-lint compiled from source against the project
// toolchain, so that its analyzers understand the Go version in go.mod.
func golangciBase(source *dagger.Directory) *dagger.Container {
	return goBase(source).
		WithExec([]string{
			"go", "install",
			"github.com/golangci/golangci-lint/v2/cmd/golangci-lint@" + golangciLint,
		})
}
