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
	acceptanceSHA256Secret = "c2hhMjU2LXNlY3JldC1mb3ItdGhlLWFjY2VwdGFuY2U=" // gitleaks:allow (throwaway)
	acceptanceMD5Secret    = "bWQ1LXNlY3JldC1mb3ItdGhlLWFjY2VwdGFuY2UtdGVzdA==" // gitleaks:allow (throwaway)
)

// TestAcceptance runs cert-manager in a k3s cluster, and makes it obtain
// certificates from Pebble through tsigoat: a wildcard and apex certificate
// with an explicit HMAC-SHA256 key, one with the HMAC-MD5 default of
// cert-manager against a key that opts into it, and one on a zone open to
// unsigned updates. PowerDNS, tsigoat and Pebble run as Dagger services,
// which the pods reach by address.
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
	pdns := asPowerDNSService(pdnsServer)
	tsigoat := m.e2eImage().
		WithServiceBinding("pdns", pdns).
		WithNewFile("/etc/tsigoat/config.yaml", acceptanceConfig()).
		WithExposedPort(e2eDNSPort, dagger.ContainerWithExposedPortOpts{Protocol: dagger.NetworkProtocolTcp}).
		WithExposedPort(e2eDNSPort, dagger.ContainerWithExposedPortOpts{Protocol: dagger.NetworkProtocolUdp}).
		AsService(dagger.ContainerAsServiceOpts{
			Args: []string{"/usr/local/bin/tsigoat", "serve", "--log-level", "debug"},
		})
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
		WithServiceBinding("tsigoat", tsigoat).
		WithServiceBinding("pebble", pebble).
		WithServiceBinding("k3s", k3s).
		WithMountedCache("/kube", kubeconfig).
		WithExec([]string{"sh", "-euc", acceptanceScript()}).
		Stdout(ctx)
}

// cgroupEntrypoint makes the root cgroup of the container delegate its
// controllers, which kubelet needs under cgroup v2, as k3d and docker-in-
// docker do: the processes of the root cgroup move to a child first.
const cgroupEntrypoint = `#!/bin/sh
set -eu
if [ -f /sys/fs/cgroup/cgroup.controllers ]; then
  mkdir -p /sys/fs/cgroup/init
  xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs || :
  sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers > /sys/fs/cgroup/cgroup.subtree_control
fi
exec "$@"
`

// acceptanceConfig renders the configuration of tsigoat: a zone secured by an
// HMAC-SHA256 key and an HMAC-MD5 one, and a zone open to unsigned updates.
func acceptanceConfig() string {
	return fmt.Sprintf(`keys:
  - name: sha256.
    secret: %s
  - name: md5.
    algorithm: hmac-md5
    secret: %s
backends:
  - name: pdns
    type: powerdns
    powerdns:
      url: http://pdns:%d
      apiKey: %s
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
`, acceptanceSHA256Secret, acceptanceMD5Secret, pdnsAPIPort, e2eAPIKey)
}

// acceptanceScript creates the zones, installs cert-manager, applies the
// issuers and certificates, and waits for the certificates.
func acceptanceScript() string {
	return strings.NewReplacer(
		"@API_KEY@", e2eAPIKey,
		"@API_PORT@", strconv.Itoa(pdnsAPIPort),
		"@PDNS_PORT@", strconv.Itoa(pdnsDNSPort),
		"@DNS_PORT@", strconv.Itoa(e2eDNSPort),
		"@PEBBLE_PORT@", strconv.Itoa(pebblePort),
		"@CHART@", certManagerChart,
		"@SHA256_SECRET@", acceptanceSHA256Secret,
		"@MD5_SECRET@", acceptanceMD5Secret,
	).Replace(`
address() { getent hosts "$1" | awk '{ print $1; exit }'; }
pdns=$(address pdns)
tsigoat=$(address tsigoat)
pebble=$(address pebble)
echo "== PowerDNS $pdns, tsigoat $tsigoat, Pebble $pebble"

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

echo "== installing cert-manager @CHART@"
helm install cert-manager oci://quay.io/jetstack/charts/cert-manager --version @CHART@ \
  --namespace cert-manager --create-namespace --set crds.enabled=true \
  --set "extraArgs={--dns01-recursive-nameservers-only,--dns01-recursive-nameservers=$pdns:@PDNS_PORT@}" \
  --wait --timeout 5m > /dev/null

echo "== issuing certificates"
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
            nameserver: "$tsigoat:@DNS_PORT@"
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
            nameserver: "$tsigoat:@DNS_PORT@"
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
            nameserver: "$tsigoat:@DNS_PORT@"
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
  exit 1
fi
kubectl get certificate -n default
echo "== OK"
`)
}
