# Contributing

## Quick start

```sh
git clone https://github.com/enix/tsigoat.git
cd tsigoat
direnv allow        # or: nix develop — or install the tools by hand, see below
task check:quick    # formatting, Go lint, unit tests
```

## Prerequisites

### The Nix way (recommended)

[Nix][nix] with flakes, and optionally [direnv][direnv]. The dev shell of
`flake.nix` provides Go, Task, GoReleaser, cosign, the DNS tools (`dig`,
`nsupdate`, `tsig-keygen`) and the analysis tools. Its hook also provisions the
Dagger CLI at the version written in `dagger.json`.

### Without Nix

- Go, any recent version: `GOTOOLCHAIN=auto` fetches the one of `go.mod`;
- [Task][task];
- Docker or Podman, which Dagger uses to run its engine;
- optionally GoReleaser, for local image builds.

The Taskfile provisions the Dagger CLI itself through `scripts/dagger-cli.sh`.

## Toolchain

| Tool | Role |
| --- | --- |
| [Task][task] (`Taskfile.yml`) | The developer façade: `task --list` shows everything |
| [Dagger][dagger] (`dagger.json`, `dagger/`) | Sandboxed QA pipelines — lint, tests, security scans — that run identically locally and in CI |
| [GoReleaser][goreleaser] (`.goreleaser.yaml`) | Binaries and container images, for local snapshots and for releases |
| [Renovate][renovate] (`renovate.json5`) | Dependency updates, self-hosted through a GitHub App |
| [Nix][nix] (`flake.nix`) | The development shell |

Single sources of truth:

- the Go toolchain is the `toolchain` directive of `go.mod`, which the tests,
  the releases and CodeQL use alike through `GOTOOLCHAIN=auto` and
  `setup-go`; the golang image of `dagger/base.go` matches it, which
  `task check:toolchain` checks, and Renovate moves them together;
- the Dagger version is the `engineVersion` of `dagger.json`; the CLI script,
  the CI composite action and Renovate all read it from there.

## Daily workflows

| Goal | Command |
| --- | --- |
| Every gate CI runs | `task check` |
| Short loop before pushing | `task check:quick` |
| Unit tests | `task test:unit` |
| End-to-end scenarios and fault injection | `task test:e2e` (`PDNS_VERSION=4.9` for the other PowerDNS line), or `task test:e2e:dev` against `task dev` |
| Real DNS clients | `task test:clients` (nsupdate), `task test:acme` (lego and certbot with Pebble) |
| Webhook example | `task test:webhook`: nsupdate through tsigoat to `examples/webhook/webhook.py` |
| Scenarios against BIND 9 | `task test:differential`; intended divergences go to `test/differential/divergences.yaml` |
| Hosted providers, for real | `task test:live`, with your test zones and credentials, see [Live tests](#live-tests) |
| Helm chart | `task lint:helm`, `task test:helm`; `task doc:helm` after a change to `chart/values.yaml` |
| cert-manager in Kubernetes | `task test:acceptance`, which installs the chart in k3s inside Dagger; nightly in CI |
| Fuzzing | `task test:fuzz`, `FUZZTIME=10m` for longer runs; nightly in CI |
| Linters | `task lint`, or `task lint:go`, `lint:markdown`, `lint:actions`... |
| Security scans | `task security` |
| Development backend | `task dev`, then `task dev:run` in another terminal |
| Local binary or images | `task build:binary:host`, `task build:image:host` |

The end-to-end tests run entirely inside Dagger: tsigoat, PowerDNS, the DNS
and ACME clients, toxiproxy and even the k3s cluster are containers on a
private network, so no port is published on the host and parallel runs do not
collide.

### Test scenarios

Each file of `test/scenario/scenarios/` is a scenario: the zone before the
test, the requests sent to tsigoat and the expected outcome. Adding a test
case usually means adding a file. Prerequisites and updates follow the syntax
of `nsupdate`:

```yaml
description: The "name is not in use" prerequisite holds, so the update applies.
refs: ["RFC 2136 2.4.5", "RFC 2136 3.2.1"]
zone:
  records:
    - www 300 IN A 192.0.2.1
requests:
  - prerequisites:
      - nxdomain new
    updates:
      - add new 300 IN TXT "fresh"
expect:
  records:
    - www 300 IN A 192.0.2.1
    - new 300 IN TXT "fresh"
```

Every scenario runs twice: in-process on the in-memory backend with the unit
tests (`go test ./internal/app/`), and against PowerDNS with `task test:e2e`.
Zones may also carry a `policy`, and requests may be SOA queries
(`opcode: query`), whose answers `expect` can check.

A scenario that fails because of a known defect carries `knownDefect`: the
suites report it as skipped while it fails, and fail as soon as it passes, so
that the marker is removed together with the fix.

### Live tests

The unit tests run the backends of Cloudflare, OVHcloud and Scaleway against
simulations of their APIs. `task test:live` runs them against the providers
themselves, with the test zones and the credentials that you bring, for the
providers that you can test:

1. Copy `test/live/live.example.yaml` to `tmp/live.yaml`, which git ignores:
   an ordinary configuration of tsigoat. Keep the backends of the providers
   that you have, and set one test zone for each, with credentials restricted
   to it.
2. Run `task test:live`; `TSIGOAT_LIVE_CONFIG` names another configuration
   file.

For every zone of the configuration, the tests write below
`tsigoat-test.<zone>` alone: they run the conformance suite of the backends,
then the challenges of a certificate for `tsigoat-test.<zone>` and its
wildcard, through tsigoat. They delete what they wrote, and what an
interrupted run left. The expectations of each provider, such as the cases
that its backend must turn down, live with its simulation, in
`internal/backend/*/…test`: a live test that tells otherwise points at a
simulation to correct, then at the backend.

### Helm chart

`chart/values.yaml` is the source of the documentation and of the schema of
the values: a `# --` comment describes each value for helm-docs, and a
`# @schema` block constrains it for helm-schema, with an explicit `type`.
`task doc:helm` regenerates `chart/README.md`, from `chart/README.md.gotmpl`,
and `chart/values.schema.json`; CI fails when they are stale.

`task test:helm` renders the chart with every values file of `examples/helm`
and `test/chart/valid`, validates the rendered configuration with the rules of
tsigoat, in the files and environment that the pod would see, and checks that
ports, probes, mounts and selectors agree. Each file of `test/chart/invalid`
must fail with the messages of its `.expect.txt` file, and
`test/chart/alerts.test.yaml` holds the unit tests of the alerts, for
promtool.

## Conventions

### Language

Everything in the repository is written in English: code, comments,
documentation, commit messages, pull requests and issues.

### Commit messages

[Conventional Commits][conventional-commits]. GoReleaser builds the public
changelog from them, and svu the version of the next release, so the type
matters:

- `feat:` new user-visible behavior;
- `fix:` bug fix;
- `perf:` performance improvement;
- `security:` fix or hardening that addresses a vulnerability;
- `deps:` dependency bump;
- `docs:` documentation only;
- `chore:`, `ci:`, `refactor:`, `test:`, `build:` stay out of the changelog.

A breaking change takes a `!` after the type and a `BREAKING CHANGE:` footer.
A `feat:` makes the next release a minor version, as a breaking change does
while tsigoat is in 0.x; anything else, a patch.

### Code style

- `golangci-lint` must pass clean with the repository configuration. When a
  check is wrong for a specific line, prefer `//nolint:<linter> // <reason>`
  over disabling it globally.
- Tests sit next to the code as `*_test.go`; table-driven tests for parsers and
  anything with many similar cases.
- Code that consumes untrusted bytes carries `Fuzz*` targets.
- Comments explain why, not what.

### Documentation

The README presents tsigoat and links to `docs/`, which holds the user
documentation, by subject, and the architecture for contributors: a change of
behavior updates the page that describes it. `docs/local/` is ignored by git,
for working notes that stay on one machine.

## Releases

A maintainer dispatches the [Tag a release](.github/workflows/tag.yaml)
workflow on `main`. [svu][svu] computes the version from the Conventional
Commits since the last release, or the next release candidate of it,
`vX.Y.Z-rc.N`, when the box is ticked; `task release:next` prints it
beforehand. The workflow tags the commit, then starts the release workflow on
the tag: it runs the quality gates, then GoReleaser builds and signs the
binaries and images and leaves a draft GitHub Release, which the maintainer
reviews and publishes. The Helm chart takes the version of the tag, and is
pushed to its OCI registry and signed after the images. A maintainer may
also push a version tag, which starts the release workflow alike.

Publishing the release announces it on Slack, with its notes, through the
incoming webhook of the `SLACK_WEBHOOK` secret; the
[Announce a release](.github/workflows/announce.yaml) workflow fails
without it.

[nix]: https://nixos.org/
[direnv]: https://direnv.net/
[task]: https://taskfile.dev/
[dagger]: https://dagger.io/
[goreleaser]: https://goreleaser.com/
[svu]: https://github.com/caarlos0/svu
[renovate]: https://docs.renovatebot.com/
[conventional-commits]: https://www.conventionalcommits.org/
