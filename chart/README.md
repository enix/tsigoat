# tsigoat

An RFC 2136 to DNS provider API proxy, authenticated with TSIG: DNS clients send RFC 2136 updates signed
with TSIG keys, and tsigoat applies them through the API of the DNS provider,
within the names and types that each key may update. Its founding use is the
ACME DNS-01 challenge of cert-manager, whose key only reaches the
`_acme-challenge` records and never holds the API key of the provider.

The [documentation of tsigoat](https://github.com/enix/tsigoat/tree/main/docs)
describes its configuration, its clients and its operations; this page covers
the chart.

## Installing

The chart needs Kubernetes 1.26 or later, which serves UDP and TCP on one
LoadBalancer port, and Helm 3.8 or later, which installs charts from OCI
registries.

tsigoat runs under the restricted Pod Security profile. Create its namespace,
and the Secret that holds the TSIG secrets and the API key of the provider:

```sh
kubectl create namespace tsigoat
kubectl label namespace tsigoat pod-security.kubernetes.io/enforce=restricted
kubectl -n tsigoat create secret generic tsigoat-secrets \
  --from-literal=cert-manager="$(openssl rand -base64 32)" \
  --from-literal=powerdns-api-key=...
```

Write the configuration of tsigoat under `config`, which reads the secrets
from the files of that Secret, in `/run/secrets/tsigoat`:

```yaml
# values.yaml
config:
  keys:
    - name: cert-manager.
      secretFile: /run/secrets/tsigoat/cert-manager
  backends:
    - name: pdns
      type: powerdns
      powerdns:
        url: http://pdns-api.powerdns.svc.cluster.local:8081
        apiKeyFile: /run/secrets/tsigoat/powerdns-api-key
  zones:
    - name: example.com.
      policy:
        - key: cert-manager.
          acme: ["example.com.", "**.example.com."]
secret:
  existingSecret: tsigoat-secrets
```

Then install the chart, from its OCI registry:

```sh
helm -n tsigoat install tsigoat oci://quay.io/enix/charts/tsigoat --values values.yaml
```

or from the Helm repository of charts.enix.io:

```sh
helm repo add enix https://charts.enix.io
helm -n tsigoat install tsigoat enix/tsigoat --values values.yaml
```

cert-manager reaches tsigoat at `tsigoat.tsigoat.svc.cluster.local:53`, see
[the clients](https://github.com/enix/tsigoat/blob/main/docs/clients.md#cert-manager).
[examples/helm](https://github.com/enix/tsigoat/tree/main/examples/helm) holds
complete values files.

## Configuration

`config` holds the configuration file of tsigoat, as
[its reference](https://github.com/enix/tsigoat/blob/main/docs/configuration.md)
describes it, without `listen` and `admin`: the chart sets the listen
addresses. The chart refuses a configuration without zones or backends, and
one that writes a secret inline, which would land in a ConfigMap: the values
of the headers of a webhook too, since the chart cannot tell a secret header
from another.

The secrets, the TSIG secrets of the clients and those of the backends, come
from one of:

- `secret.existingSecret`, a Secret created apart from the chart, which keeps
  the secrets out of the Helm release;
- `secret.files`, the files of a Secret that the chart creates;
- environment variables of `extraEnv`, read with `secretEnv` and `apiKeyEnv`.

In front of BIND or another name server that implements RFC 2136, an
`rfc2136` backend relays the updates with a key of tsigoat, see
[RFC 2136 servers](https://github.com/enix/tsigoat/blob/main/docs/rfc2136.md)
and `examples/helm/bind-relay.values.yaml`. For a provider that tsigoat does
not support, a `webhook` backend posts the updates to an endpoint of yours,
see [Webhooks](https://github.com/enix/tsigoat/blob/main/docs/webhook.md).

tsigoat reads its configuration and its secrets at startup. The chart
restarts it when `config` or `secret.files` changes; after a change to an
existing Secret, restart it yourself:

```sh
kubectl -n tsigoat rollout restart deployment tsigoat
```

A PowerDNS API served over HTTPS with a private certificate authority takes a
CA bundle, mounted with `extraVolumes` and `extraVolumeMounts`, and named by
the `caFile` of the backend.

## Exposing tsigoat

The DNS Service listens on port 53 over UDP and TCP. A `ClusterIP` Service,
the default, serves the clients of the cluster, such as cert-manager. To
serve clients outside of it, set `service.type` to `LoadBalancer` or
`NodePort`; then restrict the sources with `service.loadBalancerSourceRanges`
or a NetworkPolicy, and set `service.externalTrafficPolicy` to `Local` to log
the addresses of the clients rather than those of the nodes.

A network that routes addresses to the nodes, such as addresses that it
announces through BGP, reaches a `ClusterIP` Service on its
`service.externalIPs`. Kubernetes deprecates that field, and clusters with
the `DenyServiceExternalIPs` admission plugin refuse it: where the cluster
has a load balancer, such as one that announces its addresses through BGP,
prefer a `LoadBalancer` Service. `service.extraLabels` gives the Service the
labels that an announcement or a load balancer selects. The other fields of the
Service have their values too: its IP families (`service.ipFamilyPolicy`,
`service.ipFamilies`), its routing inside the cluster
(`service.internalTrafficPolicy`, `service.trafficDistribution`), and those
of a load balancer (`service.loadBalancerIP`,
`service.allocateLoadBalancerNodePorts`, `service.healthCheckNodePort`).

The administration server, which serves the probes and the metrics, has no
authentication: it has its own Service, always of type `ClusterIP`.

## Replicas

tsigoat runs two replicas by default, with a rolling update and a
PodDisruptionBudget, so that one of them may stop while the other serves. Each
pod serializes the updates of a zone; the records that an update adds and
removes apply to the records as they stand, so that the pods keep the records
of each other's updates, such as the challenges of a certificate and of its
wildcard, on the hosted providers and on PowerDNS since 4.9.12 and 5.0.2. A
change of TTL, prerequisites and CNAME transitions are serialized within one
pod alone: see
[Several instances](https://github.com/enix/tsigoat/blob/main/docs/operations.md#several-instances).
To keep every guarantee of RFC 2136, or in front of an older PowerDNS, set
`replicaCount` to 1, and `strategy.type` to `Recreate`, which stops the old
pod before it starts the new one during a rollout alone: a pod deleted by hand
or evicted gets its replacement at once, while it finishes its updates in
progress, for 26 seconds at most. Avoid deleting the pod while updates run.
`service.sessionAffinity` set to `ClientIP` sends the requests of
a client to one pod, which keeps these guarantees between the updates of that
client, not between clients. `topologySpreadConstraints` spreads the replicas
over nodes or zones.

## Monitoring

With the Prometheus operator, `serviceMonitor.enabled` scrapes the metrics of
tsigoat, and `prometheusRules.enabled` adds its alerts:

| Alert | Fires when | Severity |
| --- | --- | --- |
| `TsigoatBackendErrors` | Calls to a backend fail for 10 minutes | warning |
| `TsigoatUncertainUpdates` | An update may have applied in part, within 15 minutes | warning |
| `TsigoatUpdatesFailing` | Updates of a zone fail with SERVFAIL for 10 minutes | warning |
| `TsigoatSignatureFailures` | Requests fail TSIG verification more than once every ten seconds, for 15 minutes | info |
| `TsigoatLegacyAlgorithm` | A key signed with HMAC-MD5 or HMAC-SHA1 within a day | info |

[The operations guide](https://github.com/enix/tsigoat/blob/main/docs/operations.md#alerts)
tells what to do about each. `prometheusRules.disabledAlerts` leaves alerts
out, and `prometheusRules.alertLabels` labels them, for routing or to change
their severity. The alerts select the metrics of the release by namespace and
by the job of the ServiceMonitor; with another scrape configuration, set
`prometheusRules.selector`.

## Image

The chart of a release pulls its image by digest. The release writes into
`image.digests` the digest of each of its tags: the digest of the image of
every platform, so that each node pulls its own, and the same on ghcr.io,
quay.io and docker.io, which the release checks. `image.registry`, or
`global.imageRegistry`, chooses the registry; `image.tagSuffix: -busybox`, the
image with a shell, pinned as well. The signatures of the images cover these
digests.

A mirror that copies every platform, such as `crane copy` or
`skopeo copy --all`, keeps the digests; for one that does not, set
`image.pinDigest` to false. Another tag in `image.tag` is pulled by tag, and
`image.digest` pins any image.

## Verifying the chart

The chart is signed with cosign, keyless, by the release workflow, on the
tag of its version:

```sh
cosign verify quay.io/enix/charts/tsigoat:<version> \
  --certificate-identity 'https://github.com/enix/tsigoat/.github/workflows/release.yaml@refs/tags/v<version>' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

[SECURITY.md](https://github.com/enix/tsigoat/blob/main/SECURITY.md#verifying-releases)
covers the images and the binaries.

## Values

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| nameOverride | string | `""` | Partially override the name of the resources, which the release name prefixes |
| fullnameOverride | string | `""` | Fully override the name of the resources |
| namespaceOverride | string | `""` | Override the namespace of the resources |
| enabled | bool | `true` | Read by a parent chart that installs this one under a `condition`, such as `tsigoat.enabled`; the chart itself ignores it |
| extraLabels | object | `{}` | Labels added to every object of the chart; `podLabels` labels the pod. The labels of the chart win over them, and so do those of each object |
| image.registry | string | `"ghcr.io"` | Image registry; an empty string lets the container runtime choose |
| image.repository | string | `"enix/tsigoat"` | Image repository |
| image.tag | string | `""` | Image tag; the appVersion of the chart by default |
| image.tagSuffix | string | `""` | Appended to the tag: `-busybox` selects the image with a shell |
| image.digest | string | `""` | Image digest, which takes precedence over the tag |
| image.pinDigest | bool | `true` | Pull the tags of the release by the digests of `image.digests`; false pulls by tag, for a registry that holds other digests, such as a mirror that copied one platform |
| image.digests | object | the digests of the release; empty in the repository | Digests of the images of the release, by tag, which the release writes: the digest of each multi-platform image, the same on every registry |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| imagePullSecrets | list | `[]` | Names of the Secrets to pull the image with |
| replicaCount | int | `2` | Number of pods. Several pods keep the records of each other's updates, on PowerDNS since 4.9.12 and 5.0.2, but not every guarantee of RFC 2136 across pods. 1, with the `Recreate` strategy, keeps them all, but while a pod deleted or evicted outside a rollout finishes its updates beside its replacement: see [Replicas](#replicas) |
| strategy | object | a rolling update that starts a new pod before stopping an old one | Update strategy of the Deployment. Helm merges the fields given here with these defaults: with `maxSurge: 0`, set `maxUnavailable` above 0 too |
| podDisruptionBudget.enabled | bool | `true` | Create a PodDisruptionBudget, with more than one replica |
| podDisruptionBudget.maxUnavailable | int | `1` | Pods that a voluntary disruption, such as the drain of a node, may stop at once: a number, or a percentage such as `50%` |
| config | object | none: the chart refuses to install without zones and backends | Configuration of tsigoat: `keys`, `backends` and `zones`, as [docs/configuration.md](https://github.com/enix/tsigoat/blob/main/docs/configuration.md) describes them. The chart sets the listen addresses itself. Secret files are read from `/run/secrets/tsigoat`, see `secret`. |
| secret.existingSecret | string | `""` | Name of an existing Secret, mounted in `/run/secrets/tsigoat`, whose keys the configuration reads with `secretFile` and `apiKeyFile` |
| secret.files | object | `{}` | Files of a Secret that the chart creates and mounts in `/run/secrets/tsigoat`, by file name; prefer `existingSecret`, which keeps the secrets out of the release |
| log.format | string | `"json"` | Log format |
| log.level | string | `"info"` | Log level |
| listenHost | string | `"[::]"` | Host part of the listen addresses in the pod: `[::]` serves IPv4 and IPv6, `0.0.0.0` serves IPv4 on nodes without IPv6; the chart puts an IPv6 address in brackets |
| service.type | string | `"ClusterIP"` | Type of the DNS Service: `LoadBalancer` or `NodePort` exposes tsigoat out of the cluster |
| service.port | int | `53` | DNS port of the Service, for both UDP and TCP |
| service.nodePort | int | `0` | Node port for both UDP and TCP, with `NodePort` and `LoadBalancer`; 0 lets Kubernetes choose |
| service.annotations | object | `{}` | Annotations of the DNS Service, such as those of a cloud load balancer |
| service.extraLabels | object | `{}` | Labels of the DNS Service, such as those that a BGP advertisement or a load balancer selects; they win over `extraLabels`, and the labels of the chart over both |
| service.clusterIP | string | `""` | Cluster IP of the DNS Service, in the service range of the cluster; Kubernetes assigns one when empty |
| service.externalIPs | list | `[]` | Addresses out of the cluster that reach the DNS Service, such as those that the network announces through BGP; a `ClusterIP` Service serves them. Kubernetes deprecates this field, which some clusters refuse: a `LoadBalancer` Service serves such addresses where the cluster has a load balancer |
| service.ipFamilyPolicy | string | `""` | IP family policy of the DNS Service; `SingleStack` when empty |
| service.ipFamilies | list | `[]` | IP families of the DNS Service, the first one being that of its cluster IP; the families of the cluster when empty |
| service.internalTrafficPolicy | string | `""` | internalTrafficPolicy of the DNS Service: `Local` sends the requests of the pods of a node to the tsigoat pods of that node alone |
| service.trafficDistribution | string | `""` | trafficDistribution of the DNS Service, such as `PreferSameZone`, which prefers the pods of the zone of the client |
| service.externalTrafficPolicy | string | `""` | externalTrafficPolicy of a `NodePort` or `LoadBalancer` Service, or of one with `externalIPs`: `Local` keeps the addresses of the clients in the logs |
| service.healthCheckNodePort | int | `0` | Node port of the health check of a `LoadBalancer` Service whose `externalTrafficPolicy` is `Local`; 0 lets Kubernetes choose |
| service.loadBalancerSourceRanges | list | `[]` | Sources allowed to reach a `LoadBalancer` Service, as CIDR blocks |
| service.loadBalancerClass | string | `""` | Class of a `LoadBalancer` Service |
| service.loadBalancerIP | string | `""` | Address of a `LoadBalancer` Service, for the load balancers that read this field, which Kubernetes deprecates for their own annotations |
| service.allocateLoadBalancerNodePorts | bool | `true` | Allocate node ports to a `LoadBalancer` Service; false for a load balancer that reaches the pods directly |
| service.sessionAffinity | string | `"None"` | Session affinity of the DNS Service: `ClientIP` sends the requests of a client to one pod, which serializes the updates of that client, not those of other clients |
| service.sessionAffinityTimeoutSeconds | int | `10800` | How long a client stays with its pod after its last request, in seconds, with `ClientIP` |
| admin.port | int | `9153` | Port of the administration server, which serves `/healthz`, `/readyz` and `/metrics` to the probes and Prometheus, through its own `ClusterIP` Service; any port but 5353, the DNS port of the container |
| serviceMonitor.enabled | bool | `false` | Create a ServiceMonitor for the Prometheus operator |
| serviceMonitor.interval | string | `""` | Scrape interval; the default of Prometheus when empty |
| serviceMonitor.scrapeTimeout | string | `""` | Scrape timeout; the default of Prometheus when empty |
| serviceMonitor.extraLabels | object | `{}` | Labels of the ServiceMonitor, such as those that Prometheus selects; they win over `extraLabels`, and the labels of the chart over both |
| serviceMonitor.relabelings | list | `[]` | Relabelings of the targets |
| serviceMonitor.metricRelabelings | list | `[]` | Relabelings of the metrics |
| prometheusRules.enabled | bool | `false` | Create a PrometheusRule with the alerts of tsigoat |
| prometheusRules.extraLabels | object | `{}` | Labels of the PrometheusRule, such as those that Prometheus selects; they win over `extraLabels`, and the labels of the chart over both |
| prometheusRules.alertLabels | object | `{}` | Labels added to every alert, which override the severity of the alerts too |
| prometheusRules.selector | string | `""` | PromQL label matchers that select the metrics of the release, such as `job="tsigoat"`; the namespace of the release and the job of the ServiceMonitor by default |
| prometheusRules.disabledAlerts | list | `[]` | Alerts to leave out, by name: `TsigoatBackendErrors`, `TsigoatUncertainUpdates`, `TsigoatUpdatesFailing`, `TsigoatSignatureFailures`, `TsigoatLegacyAlgorithm` |
| serviceAccount.create | bool | `true` | Create a ServiceAccount; tsigoat makes no call to the Kubernetes API |
| serviceAccount.name | string | `""` | Name of the ServiceAccount; the name of the release by default |
| serviceAccount.annotations | object | `{}` | Annotations of the ServiceAccount |
| podAnnotations | object | `{}` | Annotations of the pod |
| podLabels | object | `{}` | Labels of the pod; its selector labels win over them |
| podSecurityContext | object | non-root, with the runtime default seccomp profile | Security context of the pod |
| securityContext | object | no privilege escalation, read-only root, no capability | Security context of the container |
| resources | object | requests of 10m CPU and 32Mi, limit of 128Mi | Resources of the container |
| livenessProbe | object | `/healthz` on the administration port | Liveness probe of the container. Helm merges the fields given here with the default: set `httpGet: null` for another kind of probe |
| readinessProbe | object | `/readyz` on the administration port | Readiness probe of the container. Helm merges the fields given here with the default: set `httpGet: null` for another kind of probe |
| extraEnv | list | `[]` | Environment variables of the container, for the `secretEnv` and `apiKeyEnv` settings of the configuration |
| extraVolumes | list | `[]` | Volumes added to the pod, such as a CA bundle for the PowerDNS API |
| extraVolumeMounts | list | `[]` | Volume mounts added to the container |
| nodeSelector | object | `{}` | Node selector of the pod |
| tolerations | list | `[]` | Tolerations of the pod |
| affinity | object | `{}` | Affinity of the pod |
| topologySpreadConstraints | list | `[]` | Topology spread constraints of the pods, such as one per node; their `labelSelector` defaults to the labels of the pods |
| priorityClassName | string | `""` | Priority class of the pod |
| terminationGracePeriodSeconds | int | `30` | Time given to the updates in progress when a pod stops: tsigoat needs 26 seconds at most |
| extraDeploy | list | `[]` | Additional objects to deploy with the release, as YAML objects or strings, both rendered as templates |
| global.imageRegistry | string | `""` | Registry of every image, which overrides `image.registry` |
