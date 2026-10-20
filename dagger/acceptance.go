package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"dagger/tsigoat/internal/dagger"
)

// Acceptance fixtures. The secrets only exist inside the ephemeral Dagger
// network of a test run.
const (
	acceptanceSHA256Secret = "c2hhMjU2LXNlY3JldC1mb3ItdGhlLWFjY2VwdGFuY2U="     // gitleaks:allow (throwaway)
	acceptanceMD5Secret    = "bWQ1LXNlY3JldC1mb3ItdGhlLWFjY2VwdGFuY2UtdGVzdA==" // gitleaks:allow (throwaway)
	// acceptanceImage names the image built from the source, which k3s
	// imports at startup: the registry does not exist, and the chart never
	// pulls it.
	acceptanceImage = "tsigoat.test/tsigoat:acceptance"
)

// TestAcceptance installs tsigoat with its Helm chart in a k3s cluster, under
// the restricted Pod Security profile, and makes cert-manager obtain
// certificates from Pebble through it: a wildcard and apex certificate with
// an explicit HMAC-SHA256 key, one with the HMAC-MD5 default of cert-manager
// against a key that opts into it, and one on a zone open to unsigned
// updates. The image comes from the Dockerfile of the release, with tsigoat
// compiled from the source. PowerDNS and Pebble run as Dagger services, which
// the pods reach by address.
func (m *Tsigoat) TestAcceptance(
	ctx context.Context,
	// PowerDNS release line to test against: "4.9" or "5.0".
	// +optional
	// +default="5.0"
	pdnsVersion string,
) (string, error) {
	pdnsServer, err := powerDNS(pdnsVersion, e2eAPIKey)
	if err != nil {
		return "", err
	}
	image, err := m.chartImageTarball(ctx, acceptanceImage)
	if err != nil {
		return "", err
	}
	pdns := asPowerDNSService(pdnsServer)
	pebble := dag.Container().
		From(pebbleImage).
		WithServiceBinding("pdns", pdns).
		WithEnvVariable("PEBBLE_VA_NOSLEEP", "1").
		WithEnvVariable("PEBBLE_WFE_NONCEREJECT", "0").
		WithExposedPort(pebblePort).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"/app", "-config", "test/config/pebble-config.json", "-dnsserver", fmt.Sprintf("pdns:%d", pdnsDNSPort)},
		})

	// k3s writes its kubeconfig into a cache volume that the driver mounts
	// too: one volume per run, so that no stale kubeconfig lingers.
	kubeconfig := dag.CacheVolume("tsigoat-acceptance-kubeconfig-" + strconv.FormatInt(time.Now().UnixNano(), 36))
	k3s := dag.Container().
		From(k3sImage).
		WithNewFile("/usr/local/bin/cgroup-entrypoint.sh", cgroupEntrypoint, dagger.ContainerWithNewFileOpts{Permissions: 0o755}).
		WithMountedCache("/etc/rancher/k3s", kubeconfig).
		WithMountedTemp("/var/lib/rancher/k3s").
		WithMountedFile("/images/tsigoat.tar", image).
		WithMountedTemp("/var/lib/kubelet").
		WithMountedTemp("/var/lib/cni").
		WithMountedTemp("/var/log").
		WithExposedPort(6443).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{
				"/usr/local/bin/cgroup-entrypoint.sh", "k3s", "server",
				"--disable=traefik,metrics-server", "--tls-san=k3s",
				"--egress-selector-mode=disabled", "--write-kubeconfig-mode=644",
			},
			InsecureRootCapabilities: true,
		})

	return dag.Container().
		From(kubectlImage).
		WithServiceBinding("pdns", pdns).
		WithServiceBinding("pebble", pebble).
		WithServiceBinding("k3s", k3s).
		WithMountedCache("/kube", kubeconfig).
		WithDirectory("/chart", m.Source.Directory("chart")).
		WithExec([]string{"sh", "-euc", acceptanceScript()}).
		Stdout(ctx)
}

// cgroupEntrypoint makes the root cgroup of the container delegate its
// controllers, which kubelet needs under cgroup v2, as k3d and docker-in-
// docker do: the processes of the root cgroup move to a child first. It also
// hands the image archives of /images to k3s, which imports them at startup:
// they cannot be mounted into its data directory, a mount of its own.
const cgroupEntrypoint = `#!/bin/sh
set -eu
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  mkdir -p /sys/fs/cgroup/init
  xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || :
  sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers > /sys/fs/cgroup/cgroup.subtree_control
fi
if [ -d /images ]; then
  mkdir -p /var/lib/rancher/k3s/agent/images
  cp /images/*.tar /var/lib/rancher/k3s/agent/images/
fi
exec "$@"
`

// acceptanceScript creates the zones, installs tsigoat with its chart and
// cert-manager, applies the issuers and certificates, and waits for the
// certificates. tsigoat serves a zone secured by an HMAC-SHA256 key and an
// HMAC-MD5 one, and a zone open to unsigned updates.
func acceptanceScript() string {
	registry, rest, _ := strings.Cut(acceptanceImage, "/")
	repository, tag, _ := strings.Cut(rest, ":")
	return strings.NewReplacer(
		"@API_KEY@", e2eAPIKey,
		"@API_PORT@", strconv.Itoa(pdnsAPIPort),
		"@PDNS_PORT@", strconv.Itoa(pdnsDNSPort),
		"@PEBBLE_PORT@", strconv.Itoa(pebblePort),
		"@CHART@", certManagerChart,
		"@SHA256_SECRET@", acceptanceSHA256Secret,
		"@MD5_SECRET@", acceptanceMD5Secret,
		"@IMAGE_REGISTRY@", registry,
		"@IMAGE_REPOSITORY@", repository,
		"@IMAGE_TAG@", tag,
	).Replace(`
address() { getent hosts "$1" | awk '{ print $1; exit }'; }
pdns=$(address pdns)
pebble=$(address pebble)
echo "== PowerDNS $pdns, Pebble $pebble"

for zone in secure.test. open.test.; do
  curl -fsS -X POST -H "X-API-Key: @API_KEY@" -H "Content-Type: application/json" \
    -d "{\"name\": \"$zone\", \"kind\": \"Native\", \"nameservers\": [\"ns1.$zone\"]}" \
    "http://pdns:@API_PORT@/api/v1/servers/localhost/zones" > /dev/null
done

echo "== waiting for k3s"
for i in $(seq 1 90); do [ -s /kube/k3s.yaml ] && break; sleep 2; done
export KUBECONFIG=/tmp/kubeconfig
sed 's#https://127.0.0.1:6443#https://k3s:6443#' /kube/k3s.yaml > "$KUBECONFIG"
for i in $(seq 1 90); do [ -n "$(kubectl get nodes -o name 2>/dev/null)" ] && break; sleep 2; done
kubectl wait --for=condition=Ready node --all --timeout=180s

echo "== installing tsigoat with its chart"
kubectl create namespace tsigoat
kubectl label namespace tsigoat pod-security.kubernetes.io/enforce=restricted
kubectl -n tsigoat create secret generic tsigoat-secrets \
  --from-literal=sha256="@SHA256_SECRET@" \
  --from-literal=md5="@MD5_SECRET@" \
  --from-literal=pdns-api-key="@API_KEY@"
cat > /tmp/values.yaml <<VALUES
image:
  registry: @IMAGE_REGISTRY@
  repository: @IMAGE_REPOSITORY@
  tag: @IMAGE_TAG@
  pullPolicy: Never
log:
  level: debug
config:
  keys:
    - name: sha256.
      secretFile: /run/secrets/tsigoat/sha256
    - name: md5.
      algorithm: hmac-md5
      secretFile: /run/secrets/tsigoat/md5
  backends:
    - name: pdns
      type: powerdns
      powerdns:
        url: http://$pdns:@API_PORT@
        apiKeyFile: /run/secrets/tsigoat/pdns-api-key
  zones:
    - name: secure.test.
      policy:
        - key: sha256.
          names: ["_acme-challenge.secure.test.", "_acme-challenge.**.secure.test."]
          types: [TXT]
        - key: md5.
          names: ["_acme-challenge.**.secure.test."]
          types: [TXT]
    - name: open.test.
      allowUnauthenticated: true
secret:
  existingSecret: tsigoat-secrets
VALUES
if ! helm install tsigoat /chart --namespace tsigoat --values /tmp/values.yaml --wait --timeout 3m; then
  kubectl -n tsigoat get all,events -o wide || true
  kubectl -n tsigoat describe pods || true
  kubectl -n tsigoat logs deploy/tsigoat --tail=50 || true
  exit 1
fi
kubectl -n tsigoat exec deploy/tsigoat -- /tsigoat check-config --backends
nameserver=tsigoat.tsigoat.svc.cluster.local:53

echo "== installing cert-manager @CHART@"
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager --version @CHART@ \
  --namespace cert-manager --create-namespace --set crds.enabled=true \
  --set "extraArgs={--dns01-recursive-nameservers-only,--dns01-recursive-nameservers=$pdns:@PDNS_PORT@}" \
  --wait --timeout 5m > /dev/null

echo "== issuing certificates through $nameserver"
kubectl apply -f - <<MANIFESTS
apiVersion: v1
kind: Secret
metadata: {name: tsig-sha256, namespace: cert-manager}
stringData: {secret: "@SHA256_SECRET@"}
---
apiVersion: v1
kind: Secret
metadata: {name: tsig-md5, namespace: cert-manager}
stringData: {secret: "@MD5_SECRET@"}
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: sha256}
spec:
  acme:
    server: https://$pebble:@PEBBLE_PORT@/dir
    skipTLSVerify: true
    privateKeySecretRef: {name: acme-sha256}
    solvers:
      - dns01:
          rfc2136:
            nameserver: $nameserver
            tsigKeyName: sha256.
            tsigAlgorithm: HMACSHA256
            tsigSecretSecretRef: {name: tsig-sha256, key: secret}
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: md5-default}
spec:
  acme:
    server: https://$pebble:@PEBBLE_PORT@/dir
    skipTLSVerify: true
    privateKeySecretRef: {name: acme-md5}
    solvers:
      - dns01:
          rfc2136:
            nameserver: $nameserver
            tsigKeyName: md5.
            tsigSecretSecretRef: {name: tsig-md5, key: secret}
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata: {name: open}
spec:
  acme:
    server: https://$pebble:@PEBBLE_PORT@/dir
    skipTLSVerify: true
    privateKeySecretRef: {name: acme-open}
    solvers:
      - dns01:
          rfc2136:
            nameserver: $nameserver
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: secure, namespace: default}
spec:
  secretName: secure-tls
  dnsNames: [secure.test, "*.secure.test"]
  issuerRef: {name: sha256, kind: ClusterIssuer}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: md5, namespace: default}
spec:
  secretName: md5-tls
  dnsNames: [md5.secure.test]
  issuerRef: {name: md5-default, kind: ClusterIssuer}
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata: {name: open, namespace: default}
spec:
  secretName: open-tls
  dnsNames: [open.test, "*.open.test"]
  issuerRef: {name: open, kind: ClusterIssuer}
MANIFESTS

if ! kubectl wait --for=condition=Ready certificate --all -n default --timeout=300s; then
  kubectl get certificate,certificaterequest,order,challenge -A -o wide || true
  kubectl describe challenge -A || true
  kubectl -n cert-manager logs deploy/cert-manager --tail=100 || true
  kubectl -n tsigoat logs deploy/tsigoat --tail=100 || true
  exit 1
fi
kubectl get certificate -n default
echo "== updates applied by tsigoat: $(kubectl -n tsigoat logs deploy/tsigoat | grep '"msg":"update"' | grep -c '"rcode":"NOERROR"')"
echo "== OK"
`)
}

// chartImageTarball returns the image of tsigoat built from the source with
// the Dockerfile of the release, as an archive that containerd imports under
// the given name.
func (m *Tsigoat) chartImageTarball(ctx context.Context, name string) (*dagger.File, error) {
	platform, err := dag.DefaultPlatform(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading the platform: %w", err)
	}
	tarball := dag.Directory().
		WithFile(string(platform)+"/tsigoat", m.binary()).
		WithFile("Dockerfile", m.Source.File("build/Dockerfile.scratch")).
		DockerBuild().
		AsTarball()
	// The archive does not name the image: containerd names what it imports
	// after the io.containerd.image.name annotation of the OCI index, and
	// after the RepoTags of the Docker manifest.
	return dag.Container().
		From(alpineImage).
		WithExec([]string{"apk", "add", "--no-cache", "jq"}).
		WithMountedFile("/in/image.tar", tarball).
		WithEnvVariable("IMAGE_NAME", name).
		WithExec([]string{"sh", "-euc", `
mkdir /image
tar -xf /in/image.tar -C /image
cd /image
jq --arg name "$IMAGE_NAME" '.manifests[0].annotations += {"io.containerd.image.name": $name}' \
  index.json > /tmp/index.json
jq --arg name "$IMAGE_NAME" '.[0].RepoTags = [$name]' manifest.json > /tmp/manifest.json
mv /tmp/index.json /tmp/manifest.json .
tar -cf /out.tar oci-layout index.json manifest.json blobs
`}).
		File("/out.tar"), nil
}
