# Project notes for Claude

tsigoat is an RFC 2136 (DNS UPDATE) to provider-API proxy, authenticated with
TSIG (RFC 8945). The founding use case is ACME DNS-01 for cert-manager: the
client holds a TSIG key restricted to `_acme-challenge` records, never the
PowerDNS API key.

## State of the code

The project restarted from a prototype, whose core has been rewritten into
`internal/` along the architecture below; the prototype is gone. What remains
before a first release: the documentation, the deployment manifests, metrics,
and end-to-end tests with real ACME clients (lego, certbot, cert-manager).

## Architecture

```text
cmd/tsigoat/           thin cobra commands: serve, check-config, version
internal/config/       strict YAML, canonical names, readable validation errors
internal/app/          wiring: config → keyring, policy, backends, zones → server
internal/dnsserver/    UDP/TCP listeners, accept func, response signing, shutdown
internal/update/       pure RFC 2136 engine: parse, prerequisites, apply → changes
internal/zone/         in-memory working set of a zone: lazy reads, mutations, diff
internal/auth/         TSIG keyring (one key = one algorithm), update policy
internal/backend/      Backend interface: Lookup(name) and atomic Apply(changes)
internal/backend/powerdns/  in-house HTTP client, generic presentation-format conversion
internal/backend/memory/    in-memory backend for tests and dry runs
internal/backend/rfc2136/   relay to a name server that implements RFC 2136, signed with tsigoat's key
internal/backend/webhook/   relay to an HTTP endpoint: one signed JSON POST per update
internal/backend/httpclient/  HTTP clients of the backends: CA bundle, no redirect by default
internal/backend/hosted/    shared by the hosted providers: RRsets from records, Diff, Limits, API client
internal/backend/cloudflare/, ovh/, scaleway/  hosted providers, each with a simulated API (*test)
internal/backend/backendtest/  conformance suite of the backends (memory, PowerDNS, simulations, live)
internal/metrics/      Prometheus collectors: responses, TSIG failures, backend calls
internal/admin/        administration HTTP server: /healthz, /readyz, /metrics
chart/                 Helm chart; README.md and values.schema.json generated
```

- The engine computes RRset-level `Replace`/`Delete` changes on an in-memory
  view and the backend applies them in one atomic call (one PowerDNS PATCH).
- One mutex per zone serialises updates in the process; a single instance is
  supported for now.
- A zone on an `rfc2136` or `webhook` backend skips the engine: once the
  policy allows an update, `backend.Relay` sends it whole to the name server or
  the endpoint, which applies it; no zone lock in the server (the webhook
  relay serializes per zone itself), `Check` for `check-config --backends`,
  `*backend.RejectionError` to turn an update down (webhook: prerequisites,
  delete of the whole apex; it drops SOA and apex NS deletions, fakes the
  SOA). The server's NOERROR, prerequisite failures,
  FORMERR and NOTZONE pass through; anything else is an error, SERVFAIL for
  the client. miekg/dns decodes RDATA-less records into typed empty structs
  that would re-encode with RDATA: the relay rewrites them (`withoutRDATA`).
- The hosted providers (Cloudflare, OVHcloud, Scaleway) store records with
  identifiers: their backends read the records of the touched names again in
  Apply, and `hosted.Diff` turns each RRset change into deletions, creations
  and TTL changes. `hosted.Limits` turns down, with a `RejectionError`, what a
  provider would not keep intact (types, TXT contents, SOA and apex NS,
  locked records such as Cloudflare's proxied ones); a provider error is
  SERVFAIL. Cloudflare and Scaleway write in one request; OVHcloud writes one
  record at a time and refreshes once, and after a failure reads the records
  again and restores them as they were. A write whose outcome stays unknown
  returns a `backend.IndeterminateError` (metrics result `indeterminate`). Backends with a
  minimum TTL implement `backend.TTLFloor`, and the server raises lower TTLs
  (`ttl_raised` in the update log). Records read from a provider are made
  canonical (wire round trip) so that they compare with the records of an
  update. In-house HTTP clients only, no provider SDK and no libdns
  (decision D12).
- Names are canonicalised (lowercase FQDN) at the edge.
- miekg/dns v1 stays, confined to the DNS-facing packages (depguard checks it).
- Logging is `log/slog`.
- TSIG keys declare their algorithm, `hmac-sha256` by default; `hmac-sha1` and
  `hmac-md5` are legacy opt-ins with startup warnings. A request signed with
  another algorithm than its key's gets BADKEY.
- Policy: the `keys` of a zone may update every RRset but the SOA; `policy`
  rules grant a key some names (`*` is one label, `**` one or more) and types;
  the SOA needs a rule that names it. Prerequisites are only allowed on names
  the key may update. Rules may bound what an update adds (`maxTTL`,
  `content: acme`, `maxRecords`); an `acme` rule compiles certificate names
  into `_acme-challenge` names, TXT, ACME challenge values, TTL ≤ 300, 10 per
  update.
  `auth.Policy.Authorize` checks a whole request, before the engine or the
  relay.
- Unsigned updates get REFUSED for unknown and forbidden zones alike; signed
  ones get NOTAUTH for unknown zones.
- Besides updates, the server answers the SOA queries of the zones it serves,
  signed or not, since lego and certbot find the zone of a name that way with
  unsigned queries; it answers NOTIMP to other queries.

## Build and test workflow

Everything goes through `Taskfile.yml` (`task --list`):

| Goal | Command | Notes |
|---|---|---|
| All CI gates | `task check` | drift checks, lint, tests, security |
| Quick loop | `task check:quick` | fmt, golangci-lint, unit tests |
| Go lint | `task lint:go` | `dagger call lint-go` (golangci-lint built against the project toolchain) |
| Unit tests | `task test:unit` | `dagger call test` (gotestsum, `-race`, `-shuffle=on`, coverage) |
| E2E scenarios | `task test:e2e` | `dagger call test-end-to-end --pdns-version=5.0`; `task test:e2e:dev` against `task dev` |
| Real clients | `task test:clients` | `dagger call test-clients`: nsupdate in a container |
| ACME flow | `task test:acme` | `dagger call test-acme`: lego and certbot get certificates from Pebble |
| BIND differential | `task test:differential` | `dagger call test-differential`: the scenarios against BIND 9, intended divergences in `test/differential/divergences.yaml`; and through tsigoat relaying to BIND, with no divergence |
| Live providers | `task test:live` | `go test -tags live ./test/live/`: conformance suite and an ACME flow against the zones and credentials of `tmp/live.yaml` (`TSIGOAT_LIVE_CONFIG`); see `test/live/live.example.yaml` |
| Helm chart | `task test:helm` | `dagger call test-helm`: `test/chart` (build tag `chart`) renders every example and fixture, then promtool and kubeconform; `task lint:helm` too |
| Chart docs | `task doc:helm` | regenerates `chart/README.md` and `chart/values.schema.json`; `task check:helm-docs` fails when stale |
| Webhook example | `task test:webhook` | `dagger call test-webhook-example`: nsupdate through tsigoat to `examples/webhook/webhook.py`, each authentication |
| cert-manager | `task test:acceptance` | `dagger call test-acceptance`: the chart in k3s, cert-manager through it, inside Dagger; nightly |
| Mutation | `task test:mutation` | `dagger call mutation`: gremlins on update, zone and auth; informational, nightly |
| Fuzzing | `task test:fuzz` | `dagger call fuzz --fuzztime=1m`: every `Fuzz*` target; 10 minutes each in the nightly workflow |
| Security | `task security` | gitleaks, govulncheck, Trivy |
| Dev backend | `task dev` + `task dev:run` | PowerDNS on :8081 (API) and :5300 (DNS); tsigoat on 127.0.0.1:10053 |

Dagger specifics:

- Function names are kebab-cased by Dagger, digits included: `TestE2E` would
  become `test-e-2-e`, hence `TestEndToEnd`.
- The PowerDNS image runs as a non-root user that cannot bind port 53 inside
  Dagger: it listens on 5300.
- Dagger health checks are meaningless for UDP ports: always expose a TCP port
  too.
- Tests and clients run as containers bound to the services; nothing is
  published on the host.
- `dagger ... up --ports` only forwards TCP: from the host, query the dev
  PowerDNS with `dig +tcp`. tsigoat itself runs natively in the dev loop, so
  UDP clients reach it directly.
- Generated bindings (`dagger/dagger.gen.go`, `dagger/internal/`) are not
  committed; run `task dagger:develop` after changing `dagger.json`.

## Test scenarios

`test/scenario/scenarios/<group>/<name>.yaml` describe a zone, the requests
sent to tsigoat (prerequisites and updates in nsupdate syntax, SOA queries,
other opcodes) and the expected outcome. `test/scenario` loads them and holds
the runner, which drives a `Target`: tsigoat in front of a backend it can
reset and read. The scenarios run twice, one zone per scenario:

- in-process on the in-memory backend, in `internal/app` (plain `go test`,
  part of the unit tests), directly, through a relaying tsigoat, and on the
  simulated APIs of Cloudflare, OVHcloud and Scaleway, whose intended
  divergences are listed in `Divergences()` of each `*test` package;
- against a tsigoat binary and PowerDNS in `test/e2e` (build tag `e2e`).

`scenario.Config` renders the tsigoat configuration of both runs, the one
place to update when the configuration format changes. A scenario failing
because of a known defect carries `knownDefect: <id>`: its failure is reported
as skipped, and the suite fails when it starts passing, so the marker must be
removed with the fix.

## Helm chart

- `chart/values.yaml` drives both generated files: `# --` comments for
  helm-docs, `# @schema` blocks for helm-schema. Always give a `type` in a
  `# @schema` block (helm-schema drops the inferred one), and
  `properties: {}` on free-form objects with defaults (it would otherwise
  forbid their unknown nested keys).
- The chart owns `listen` and `admin` of the configuration, and refuses inline
  secrets, which would land in the ConfigMap.
- `test/chart/valid` and `examples/helm/*.values.yaml` must render and pass
  the checks; `test/chart/invalid/<name>.yaml` must fail with every line of
  `<name>.expect.txt`; `test/chart/alerts.test.yaml` tests the alerts.
- The alerts link to their sections of `docs/operations.md`.

## Documentation

`README.md` presents tsigoat and links to `docs/`: `configuration.md`,
`clients.md`, `powerdns.md`, `providers.md` with `cloudflare.md`, `ovh.md`
and `scaleway.md`, `rfc2136.md`, `webhook.md`, `operations.md`,
`security.md`, and
`architecture.md` for contributors; and to `chart/README.md` for Kubernetes.
A change of behavior updates the page that describes it. `docs/local/` is ignored by git: it holds the French working
notes of the restart (analysis with the P*/A* defect identifiers, restart plan
with the D* decisions, tooling), which must never be committed.

## Conventions

- Everything in the repository is in English, but `docs/local/`.
- Conventional Commits; GoReleaser builds the changelog from them.
- golangci-lint must pass clean, without path exclusions. Every `//nolint`
  names its linter and explains why.
- Tests sit next to the code; table-driven for parsers; `Fuzz*` targets for
  code that parses untrusted bytes.
- Single sources of truth: Go version in `go.mod`, Dagger version in
  `dagger.json`, pinned images in `dagger/base.go` (tracked by Renovate).
