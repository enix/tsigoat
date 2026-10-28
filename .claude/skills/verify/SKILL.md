---
name: verify
description: Pick and run the checks of tsigoat that a change needs, the way the CI picks its jobs from the paths that changed, before the change is committed or pushed, and report their outcome. Use before committing or pushing, when asked to test or check a change, and to reproduce a test that fails under load.
---

# Verify a change

On a pull request, the Linting, Tests and Security workflows run the jobs of
the paths that changed; on `main`, they run every job. Run the same checks
locally, through `task`, before committing: the CI should only confirm them.
`task check` runs everything.

## Pick the checks

Start from the paths that changed: `git status`, and `git diff --stat
origin/main` for commits not pushed yet.

| Paths | Checks |
| --- | --- |
| Go code, `go.mod`, `go.sum`, `test/`, `.golangci.yml` | `task check:quick`, `task check:drift`, then every test that the CI runs on a Go change: `task test:e2e`, `PDNS_VERSION=4.9 task test:e2e`, `task test:clients`, `task test:acme`, `task test:differential`, `task test:webhook`, `task test:helm`, `task test:build`, `task test:packages`, `task test:release` |
| `dagger/`, `dagger.json` | the checks of every row, since they all run in Dagger: `task check` |
| `chart/`, `examples/helm/`, `test/chart/` | `task doc:helm`, then `task check:helm-docs`, `task lint:helm`, `task lint:manifests`, `task test:helm` |
| The configuration file types of `internal/config` | the Go checks, and `task doc:helm`, since the schema of the chart derives from them |
| `examples/webhook/` | `task test:webhook` |
| `.goreleaser.yaml`, `build/` | `task test:build`, `task test:packages`, and `task lint:dockerfile` for `build/Dockerfile.*` |
| `.releaserc.mjs`, `.github/release/` | `task test:release` |
| `.github/` | `task lint:actions` |
| `renovate.json5` | `task lint:renovate` |
| Markdown | `task lint:markdown`, which skips `CLAUDE.md`, `AGENTS.md` and hidden directories |
| Dependencies, images, `.trivyignore` | `task security` |

A test of the end-to-end family takes a PowerDNS version: run 4.9 and 5.0
for a change of the engine, the zones, the server or a backend. A change of
behavior also updates the page of `docs/` that describes it.

The Dagger tasks run in parallel without trouble; a first run builds the
images and takes longer.

## A test that fails under load

Tests that wait on a clock can fail on a loaded machine, as in a full `task
check`. Reproduce such a failure under load before and after the fix, and
tell the user before loading the machine: it is their workstation.

```sh
# Two busy loops per core, for five minutes at most: timeout runs them in its
# process group, and passes the signal that stops it to the whole group.
timeout 300 sh -c 'for i in $(seq $(($(nproc) * 2))); do sh -c "while :; do :; done" & done; wait' &
load=$!
go test -race -count=15 -run 'TestName' ./internal/<package>/
kill "$load"
pgrep -c -x -f 'sh -c while :; do :; done' # 0: no loop left
```

After an interrupted run, the loops stop with their timeout, and `pkill -x
-f 'sh -c while :; do :; done'` stops them at once. Match the whole command
line, with `-x`: a partial pattern also matches the shell whose command
holds it, and kills that shell.

## Report

Name the checks that ran and their outcome, with the output of a failure, and
the checks that did not run, with the reason.
