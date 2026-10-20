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

A request runs for at most ten seconds, backend calls included. On SIGINT or
SIGTERM, tsigoat stops listening on every address at once, then finishes the
requests in progress.

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

The chart runs one replica with the `Recreate` strategy, since tsigoat
serializes the updates of a zone within its process. The pod passes the
restricted Pod Security profile, and its probes use `/healthz` and `/readyz`.
The DNS Service and the Service of the administration server are apart, so
that exposing the first never exposes the second.

## Logs

tsigoat logs to the standard error, one line per event, as text or JSON.

Every update ends with one entry, `msg=update`:

| Field | Content |
| --- | --- |
| `remote` | Address of the client |
| `key` | Key that signed the update; absent when unsigned |
| `zone` | Zone of the update |
| `rcode` | Response code |
| `reason` | Why the update was rejected, for REFUSED, FORMERR, NOTZONE and failed prerequisites |
| `error` | Why it failed, for SERVFAIL |
| `changes` | RRset changes applied, such as `replace _acme-challenge.www.example.com. TXT 60 ["token"]` |
| `updates` | Updates relayed to an `rfc2136` backend, as requested, such as `add _acme-challenge.www.example.com. 60 TXT "token"` |
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
| `tsigoat_tsig_failures_total` | `error`: BADKEY, BADSIG or BADTIME |
| `tsigoat_backend_calls_total` | `backend`, `operation` (lookup, apply, or relay for an `rfc2136` backend), `result` (success or error) |
| `tsigoat_backend_call_duration_seconds` | `backend`, `operation` |
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
--backends` reads the SOA of every zone through its backend. For an `rfc2136`
backend, also check that the server knows the key of tsigoat and grants it
the updates, see [RFC 2136 servers](rfc2136.md#setting-up-the-server).

### TsigoatUpdatesFailing

Updates of a zone have failed with SERVFAIL for ten minutes. The `error`
field of their `msg=update` log entries tells why: a failing backend, which
TsigoatBackendErrors reports too, a zone missing from its backend, or a
backend too slow for the ten seconds that a request may last.

### TsigoatSignatureFailures

Requests have failed TSIG verification more than once every ten seconds, for
fifteen minutes: BADKEY for an unknown key or another algorithm than the one
of the key, BADSIG for a wrong secret, BADTIME for a clock beyond the time
margin of the signature. The `TSIG verification failed` log entries name the
client, the key and the algorithm. A steady flow from unknown clients rather
tells of a probe: restrict who reaches the DNS port.

### TsigoatLegacyAlgorithm

A key has signed requests with HMAC-MD5 or HMAC-SHA1 within a day; RFC 8945
deprecates both. tsigoat binds one algorithm to each key: move the clients
of the key to HMAC-SHA256 together with the key, or give the moved clients a
new HMAC-SHA256 key. cert-manager signs with HMAC-MD5 unless its issuer sets
`tsigAlgorithm: HMACSHA256`.
