package main

import (
	"dagger/tsigoat/internal/dagger"
)

// Pinned image versions. Renovate's regex manager tracks the
// `<name>Image = "..."` literals and the Go install versions below.
const (
	golangImage       = "golang:1.27.3-alpine@sha256:d200d2dd76b03a99b52651fd1325aff7dcd35422c35c01bac56571b0507f3deb"
	alpineImage       = "alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a"
	markdownlintImage = "davidanson/markdownlint-cli2:v0.24.0@sha256:70ead7c0352d22d04bbe612cd96b54ec591538d8f4626cafe391bb2ecf3639ca"
	actionlintImage   = "rhysd/actionlint:1.7.12@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667"
	zizmorImage       = "ghcr.io/zizmorcore/zizmor:1.31.1@sha256:42d409dbb851d4c5d35a058cf042b828bea1e3f2884378c526eb0974780e18d9"
	hadolintImage     = "hadolint/hadolint:v2.15.1@sha256:32dac94127fd60b7b7e3fbfc65e1383b9b5e25c9bfd7b8536de7a539fe68a12d"
	renovateImage     = "renovate/renovate:44.186.7@sha256:ece4f0001262b6774786d9026799a382e2beb14c7349ae45229d26284e9f8518"
	trivyImage        = "aquasec/trivy:0.76.1@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
	gitleaksImage     = "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
	pdns49Image       = "powerdns/pdns-auth-49:4.9.18@sha256:b2088f8bd0099a27a56b84837ae21ebbb45f83345bef34c55f63890148288f93"
	pdns50Image       = "powerdns/pdns-auth-50:5.0.8@sha256:c36a4ca00006fcdafe882c226d2d745291c2caab2eb461d77ff3bffa33681a2b"
	toxiproxyImage    = "ghcr.io/shopify/toxiproxy:2.13.0@sha256:5d3dae09bc185dcc5ff6cf43abf6062a4a720aff0c4306a471e773acdcd107aa"
	kubeconformImage  = "ghcr.io/yannh/kubeconform:v0.8.0@sha256:faffaf43f95aa6425306e1ab8d6fcad72acb9049158f38e574c085ea1ec0f64e"
	helmImage         = "alpine/helm:4.3.1@sha256:e3f8d5c462d75470fbb1fce79ad5c20063657096d1f98c0fcea869e2600e2e5e"
	helmDocsImage     = "jnorwood/helm-docs:v1.14.2@sha256:7e562b49ab6b1dbc50c3da8f2dd6ffa8a5c6bba327b1c6335cc15ce29267979c"
	helmSchemaImage   = "ghcr.io/dadav/helm-schema:v0.24.0@sha256:efa1a88d082728c81eb1734a263b0ec0eb353b99f49dc199f22e2567bf0fef9f"
	prometheusImage   = "quay.io/prometheus/prometheus:v3.15.1@sha256:fa3302279710be2f21a8301ec17a8b4f2301fd829bd113839b3b6b02b6f191a2"
	pebbleImage       = "ghcr.io/letsencrypt/pebble:2.10.1@sha256:ddf230642b1a584f519f32e347de1b05a6e4c1f6c35c1863b33effeab5f78199"
	legoImage         = "goacme/lego:v4.35.2@sha256:ae124a405844759b201b31efbd7a0ba302dbd16e86f2fb177c4b6db8bdc782c8"
	certbotImage      = "certbot/dns-rfc2136:v5.8.0@sha256:55d52a5de51df312cadbcce1dc105f20d639bc127699e791323c2a27db05ac1f"
	goreleaserImage   = "ghcr.io/goreleaser/goreleaser:v2.18.3@sha256:b61a4eedf5e3b1d283792dade34ee0f8c6cce3e6f1f65851d3b397b8f8a75b6d"
	nodeImage         = "node:24.22.1-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53"
	debianImage       = "debian:13.7-slim@sha256:62bd423aeee912639ca8ee681c2b762cb3e25137e0a92b20be455898a9f034ad"
	almalinuxImage    = "almalinux:9.8@sha256:9819dc675b67b595c2b59e42be7763fca1a8bb217fa5944e04daa22e9a64db16"
	k3sImage          = "rancher/k3s:v1.37.1-k3s1@sha256:ca7f37d993d82ef0dcdcfecb2e0e2618ea541dbaffc620c8cedebe01a82acd0d"
	kubectlImage      = "alpine/k8s:1.37.1@sha256:712dc5385d1c1a3f83b747fa9e40f64d433a97f72ff42f9755ff7dd1f62846e4"
	certManagerChart  = "v1.21.3" // oci://quay.io/jetstack/charts/cert-manager
	golangciLint      = "v2.15.0" // installed via `go install`
	gotestsumModule   = "v1.13.0" // ditto
	gremlinsModule    = "v0.6.0"  // ditto
	govulncheckModule = "v1.9.0"  // ditto: the scanner moves with Renovate, its database with each run
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
