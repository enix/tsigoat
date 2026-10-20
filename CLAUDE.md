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
internal/metrics/      Prometheus collectors: responses, TSIG failures, backend calls
internal/admin/        administration HTTP server: /healthz, /readyz, /metrics
```

- The engine computes RRset-level `Replace`/`Delete` changes on an in-memory
  view and the backend applies them in one atomic call (one PowerDNS PATCH).
- One mutex per zone serialises updates in the process; a single instance is
  supported for now.
- Names are canonicalised (lowercase FQDN) at the edge.
- miekg/dns v1 stays, confined to the DNS-facing packages (depguard checks it).
- Logging is `log/slog`.
- TSIG keys declare their algorithm, `hmac-sha256` by default; `hmac-sha1` and
  `hmac-md5` are legacy opt-ins with startup warnings. A request signed with
  another algorithm than its key's gets BADKEY.
- Policy: the `keys` of a zone may update every RRset but the SOA; `policy`
  rules grant a key some names (`*` is one label, `**` one or more) and types;
  the SOA needs a rule that names it. Prerequisites are only allowed on names
  the key may update.
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
  part of the unit tests);
- against a tsigoat binary and PowerDNS in `test/e2e` (build tag `e2e`).

`scenario.Config` renders the tsigoat configuration of both runs, the one
place to update when the configuration format changes. A scenario failing
because of a known defect carries `knownDefect: <id>`: its failure is reported
as skipped, and the suite fails when it starts passing, so the marker must be
removed with the fix.

## Conventions

- Everything in the repository is in English.
- Conventional Commits; GoReleaser builds the changelog from them.
- golangci-lint must pass clean, without path exclusions. Every `//nolint`
  names its linter and explains why.
- Tests sit next to the code; table-driven for parsers; `Fuzz*` targets for
  code that parses untrusted bytes.
- Single sources of truth: Go version in `go.mod`, Dagger version in
  `dagger.json`, pinned images in `dagger/base.go` (tracked by Renovate).
