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
| Helm chart | `task lint:helm`, `task test:helm`; `task doc:helm` after a change to `chart/values.yaml` or to the configuration file |
| cert-manager in Kubernetes | `task test:acceptance`, which installs the chart in k3s inside Dagger; nightly in CI |
| Fuzzing | `task test:fuzz`, `FUZZTIME=10m` for longer runs; nightly in CI |
| Linters | `task lint`, or `task lint:go`, `lint:markdown`, `lint:actions`... |
| Security scans | `task security` |
| Development backend | `task dev`, then `task dev:run` in another terminal |
| Local binary or images | `task build:binary:host`, `task build:image:host` |
| What a release builds | `task test:build`: the archives, checksums and images of every platform, started on a minimal configuration |

The end-to-end tests run entirely inside Dagger: tsigoat, PowerDNS, the DNS
and ACME clients, toxiproxy and even the k3s cluster are containers on a
private network, so no port is published on the host and parallel runs do not
collide.

On a pull request, the Linting, Tests and Security workflows run the jobs
that its changes concern. Each ends with a job, `Lint passed`, `Tests passed`
and `Security passed`, which the rules of `main` require, rather than every
job: it passes when every other job of its workflow passed or was skipped by
the paths of the change, and fails when one failed or was canceled.

The runs keep their reports as artifacts, failures included: `unit-tests`
holds the output, JUnit and coverage of the unit tests, and `fuzzing`, of the
nightly workflow, the inputs that made a fuzz target fail, at the paths where
`go test` reads them: commit them as regression cases. Locally,
`dagger call test-report export --path=report` and
`dagger call fuzz-report export --path=report` give the same.

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
and `chart/values.schema.json`, whose `config` takes the schema of the
configuration file from the types that decode it in `internal/config`; CI
fails when they are stale.

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

[Conventional Commits][conventional-commits]. semantic-release computes the
version of the next release from them, and writes its notes, so the type
matters:

- `feat:` new user-visible behavior: a minor version;
- `fix:` bug fix: a patch;
- `perf:` performance improvement: a patch;
- `security:` fix or hardening that addresses a vulnerability: a patch;
- `deps:` dependency bump, whatever the dependency: a patch;
- `docs:` documentation only: in the notes, but no release of its own;
- `chore:`, `ci:`, `refactor:`, `test:`, `build:` stay out of the notes, and
  make no release.

A breaking change takes a `!` after the type and a `BREAKING CHANGE:` footer,
in upper case; it makes a minor version while tsigoat is in 0.x.

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

`main` makes release candidates, `vX.Y.Z-rc.N`; `release`, which only moves
forward to a commit of `main`, makes stable versions, `vX.Y.Z`.

A maintainer dispatches the [Tag a release](.github/workflows/tag.yaml)
workflow on `main` for a candidate, or on `release` for a stable version, once
`release` moved forward to the commit that a candidate tested:

```sh
git push origin <commit>:release
```

[semantic-release][semantic-release] (`.releaserc.mjs`) computes the version
from the Conventional Commits since the last stable version, pushes its tag,
and leaves a draft GitHub Release with its notes: those of a stable version
hold the changes of its candidates. The workflow then starts the
[release workflow](.github/workflows/release.yaml) on the tag. Its dry run
prints the version and the notes, and tags nothing.

The release workflow runs the quality gates, then GoReleaser builds and signs
the binaries, the deb and rpm packages and the images, and attaches them to
the draft; the Helm chart takes the version of the tag, and is pushed to its
OCI registry and signed after the images. Once the draft holds every file,
the last job publishes it and announces it on Slack, with
semantic-release-slack-bot and the incoming webhook of the `SLACK_WEBHOOK`
secret. A maintainer may also push a version tag, once its draft release
exists, named after the tag and with its notes: the release workflow refuses
a tag without one.

The packages of semantic-release are pinned in `.github/release`, and move
with Renovate; `task test:release` runs semantic-release in dry runs on a
history made for it, and renders the Slack announcement.

When the release workflow fails, run its failed jobs again on the same tag:
GoReleaser replaces the files of the draft and pushes the images again. When
Tag a release created the tag but did not start the release, run the release
workflow on that tag. A tag moves only while nothing of its version left the
repository: when the quality gates fail on it, before GoReleaser ran, delete
the draft, the tag and its semantic-release note, fix `main`, and dispatch Tag
a release again, which computes the same version:

```sh
gh release delete vX.Y.Z --yes
git push origin :refs/tags/vX.Y.Z :refs/notes/semantic-release-vX.Y.Z
```

Once GoReleaser pushed an image, the version is out: a fix takes the next
version.

[nix]: https://nixos.org/
[direnv]: https://direnv.net/
[task]: https://taskfile.dev/
[dagger]: https://dagger.io/
[goreleaser]: https://goreleaser.com/
[semantic-release]: https://semantic-release.gitbook.io/
[renovate]: https://docs.renovatebot.com/
[conventional-commits]: https://www.conventionalcommits.org/
