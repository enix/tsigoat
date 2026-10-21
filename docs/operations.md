# Operations

## Command line

| Command | Purpose |
| --- | --- |
| `tsigoat serve` | Serve DNS updates until SIGINT or SIGTERM, then finish the updates in progress |
| `tsigoat check-config` | Validate the configuration and print its warnings; `--backends` also reads every zone through its backend; exit code 1 when a check fails |
| `tsigoat version` | Print the version and the build details; `--short` for the version only |

`serve` and `check-config` read `--config`, `/etc/tsigoat/config.yaml` by
default. `serve` also takes:

| Flag | Meaning |
| --- | --- |
| `--listen` | DNS address, repeatable; replaces `listen` |
| `--admin-listen` | Address of the administration server; replaces `admin.listen` |
| `--log-format` | `text`, the default, or `json` |
| `--log-level` | `debug`, `info`, the default, `warn` or `error` |
| `--auto-gomemlimit` | Set the Go memory limit from the cgroup; on by default |

A request runs for at most ten seconds, backend calls included; an update
that fails at a hosted provider may go on for up to fifteen seconds more, to
read its records back or to restore them. On SIGINT or SIGTERM, tsigoat stops
listening on every address at once, then finishes the requests in progress,
for 26 seconds at most: give it that much time to stop, as the 30 seconds of
the `terminationGracePeriodSeconds` of the chart do.

## Container images

The images are published on `ghcr.io/enix/tsigoat`, `quay.io/enix/tsigoat`
and `docker.io/enix/tsigoat`, for amd64, arm64 and riscv64:

- `<version>` and `latest` are built `FROM scratch`: the static binary and
  nothing else;
- `<version>-busybox` and `busybox` add a shell, for debugging.

Both run `serve` as user 65534, read `/etc/tsigoat/config.yaml`, listen on
port 5353 over UDP and TCP, and expose 9153 for the administration server:

```sh
docker run --rm -p 53:5353/udp -p 53:5353/tcp \
  -v "$PWD/config.yaml:/etc/tsigoat/config.yaml:ro" ghcr.io/enix/tsigoat
```

## Kubernetes

The Helm chart of [chart](../chart) deploys tsigoat; [its
README](../chart/README.md) covers its installation, its values, exposing
tsigoat out of the cluster and monitoring it.
[examples/helm](../examples/helm) holds values files, for cert-manager and
for clients outside the cluster, and a cert-manager ClusterIssuer.

The chart runs two replicas by default, with a rolling update and a
PodDisruptionBudget: [Several instances](#several-instances) tells what they
keep of RFC 2136, and how to keep it all. The pods pass the restricted Pod
Security profile, and their probes use `/healthz` and `/readyz`.
The DNS Service and the Service of the administration server are apart, so
that exposing the first never exposes the second.

## Several instances

Several instances of tsigoat may serve the same zones, such as the replicas
of the chart, so that one of them may stop. Each instance serializes the
updates of a zone; between instances, the records that an update adds and
removes apply to the records as they stand at the backend, so that concurrent
updates keep each other's records: the challenges of a certificate and of its
wildcard, sent at once to two instances, both stay. This is a deliberate
choice, for availability, and of little consequence for ACME clients, whose
updates add and remove values. A few guarantees of RFC 2136 hold within an
instance alone:

- an update that changes the TTL of an RRset replaces it whole, as its
  instance read it, and drops a record that another instance added meanwhile;
- the prerequisites of an update hold on what its instance read, not at the
  time of its write;
- an update that adds a CNAME where another instance adds other data, or the
  reverse, may leave both;
- two updates that change the same RRsets apply to each RRset in some order,
  not each one whole before the other.

To keep them all, run a single instance, or send the updates of each client
to one instance: set `service.sessionAffinity` to `ClientIP` in the chart, or
route by client in a CNI or an external load balancer. The
relays need neither: an RFC 2136 name server applies each update whole, and a
webhook endpoint applies the updates of a zone one at a time.

## Logs

tsigoat logs to the standard error, one line per event, as text or JSON.

Every update ends with one entry, `msg=update`:

| Field | Content |
| --- | --- |
| `remote` | Address of the client |
| `key` | Key that signed the update; absent when unsigned |
| `zone` | Zone of the update |
| `rcode` | Response code |
| `reason` | Why the update was rejected, for REFUSED, FORMERR, NOTZONE and failed prerequisites, or why the backend turned it down |
| `error` | Why it failed, for SERVFAIL |
| `changes` | Changes applied, such as `add _acme-challenge.www.example.com. TXT 60 ["challenge-value"]`, `remove` for the records removed, and `replace` or `delete` for whole RRsets |
| `ttl_raised` | RRsets whose TTL tsigoat raised to the minimum of the provider, such as `www.example.com. TXT 30 to 60` |
| `updates` | Updates relayed to an `rfc2136` or `webhook` backend, as requested, such as `add _acme-challenge.www.example.com. 60 TXT "challenge-value"` |
| `duration` | Time to process the update |

The level tells the outcome: `INFO` for applied updates and failed
prerequisites, `WARN` for rejected ones, `ERROR` for failures. A request whose
TSIG signature does not verify logs `TSIG verification failed` at `WARN`, with
the key, the algorithm and the TSIG error; for an algorithm mismatch, also the
algorithm of the key.

## Metrics

With `admin.listen` set, tsigoat serves over HTTP:

| Endpoint | Answer |
| --- | --- |
| `/healthz` | 200 while the process runs |
| `/readyz` | 200 while tsigoat serves DNS, 503 before and once it shuts down |
| `/metrics` | Prometheus metrics |

| Metric | Labels |
| --- | --- |
| `tsigoat_dns_responses_total` | `opcode`, `rcode`, `zone`, `key`, `algorithm` |
| `tsigoat_dns_response_duration_seconds` | `opcode` |
| `tsigoat_tsig_failures_total` | `error`: BADKEY, BADSIG, BADTIME or BADTRUNC |
| `tsigoat_backend_calls_total` | `backend`, `operation` (lookup, apply; relay and check for the `rfc2136` and `webhook` backends), `result` (success, error, or indeterminate when tsigoat could not tell whether a write applied) |
| `tsigoat_backend_call_duration_seconds` | `backend`, `operation` |
| `tsigoat_backend_last_indeterminate_timestamp_seconds` | `backend`: time of the last call whose outcome is unknown, 0 when there was none |
| `tsigoat_build_info` | `version`, `revision`, `goversion` |

The Go runtime and process metrics come too. The `zone` and `key` labels only
take configured names, empty otherwise, so that clients cannot grow the
series. `algorithm` tracks the remaining use of HMAC-MD5 and HMAC-SHA1.

The administration server has no authentication: keep it on a private
network.

## Alerts

The chart creates a PrometheusRule with the following alerts when
`prometheusRules.enabled` is set; each links to its section below.

### TsigoatBackendErrors

Calls to a backend have failed for ten minutes, and the updates of its zones
fail with SERVFAIL. The `error` field of the `msg=update` log entries tells
why. Check that tsigoat reaches the API, through network policies, name
resolution and TLS, and that its API key is valid: `tsigoat check-config
--backends` checks every zone through its backend. For an `rfc2136` backend,
also check that the server knows the key of tsigoat and grants it the
updates, see [RFC 2136 servers](rfc2136.md#setting-up-the-server); for a
`webhook` backend, the status that the endpoint answers, in the logs.

### TsigoatUncertainUpdates

tsigoat could not tell whether an update applied: a write timed out, or the
connection broke after the request left, and reading the records back did
not tell either; undoing a failed update at OVHcloud failed, or a request
that failed there may still apply; an RFC 2136 server answered unsigned, or a
webhook endpoint answered 5xx. The client got SERVFAIL, but the zone may hold
all of the update, part of it, or none. The
`msg=update` log entry, whose `error` starts with `outcome unknown`, names the
changes: compare them with the zone, through the provider, and fix it by hand
if needed. A client that retries its update brings the RRsets to their wanted
content anyway, since tsigoat reads them again.

### TsigoatUpdatesFailing

Updates of a zone have failed with SERVFAIL for ten minutes. The `error`
field of their `msg=update` log entries tells why: a failing backend, which
TsigoatBackendErrors reports too, a zone missing from its backend, or a
backend too slow for the ten seconds that a request may last.

### TsigoatSignatureFailures

Requests have failed TSIG verification more than once every ten seconds, for
fifteen minutes: BADKEY for an unknown key or another algorithm than the one
of the key, BADSIG for a wrong secret, BADTIME for a clock beyond the time
margin of the signature, BADTRUNC for a client that truncates its MACs, which
tsigoat does not accept. The `TSIG verification failed` log entries name the
client, the key and the algorithm. A steady flow from unknown clients rather
tells of a probe: restrict who reaches the DNS port.

### TsigoatLegacyAlgorithm

A key has signed requests with HMAC-MD5 or HMAC-SHA1 within a day; RFC 8945
deprecates both. tsigoat binds one algorithm to each key: move the clients
of the key to HMAC-SHA256 together with the key, or give the moved clients a
new HMAC-SHA256 key. cert-manager signs with HMAC-MD5 unless its issuer sets
`tsigAlgorithm: HMACSHA256`.
