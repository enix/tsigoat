---
name: deps
description: Update every dependency of tsigoat at once, outside the schedule of Renovate (Go modules, pinned images and tools, Dagger, GitHub Actions, the release packages, the Nix inputs), commit the updates by Renovate group, retire the Renovate pull requests that they supersede, and triage the vulnerability findings of the dependencies. Use when asked to update the dependencies, to handle a Dependabot, Trivy, govulncheck or Scorecard finding, or when a security check fails on an advisory.
---

# Update the dependencies

`renovate.json5` is the inventory: its custom managers name the write sites
that the managers of Renovate do not read, and its package rules the groups
that move together. The managers of Renovate read `go.mod`, `dagger/go.mod`,
the workflows, `.github/release/package.json`, `flake.lock` and the
Dockerfiles.

## List the updates

`task renovate:plan` runs Renovate on the working tree and lists the updates
that it would propose, by file: the package, its version and the new one; the
package rules of `renovate.json5` give their groups. Renovate leaves the indirect
requirements of the Go modules alone: `go list -m -u all`, in the main module
and in `dagger/`, lists them.

## Apply them

Move each group at all its write sites:

- Go modules: `task go:upgrade`. The `toolchain` of `go.mod` and the golang
  image of `dagger/base.go` move together: `task check:toolchain`. The
  dependencies of the Dagger SDK, in `dagger/go.mod`, move with `dagger.json`
  and `task dagger:develop`, but a vulnerability that the SDK lags behind is
  fixed with `go get` in `dagger/`, and `dagger develop` keeps the higher
  version.
- Images of `dagger/base.go` and `build/Dockerfile.*`: the tag and the digest
  of its multi-platform index, `skopeo inspect --raw
  docker://<image>:<tag> | sha256sum`.
- GitHub Actions: the commit of their tag, with the tag in a comment, `gh api
  repos/<owner>/<repo>/commits/<tag> --jq .sha`. The inputs that install a
  tool, such as the `version` of goreleaser-action and setup-helm,
  `renovate-version` and `cosign-release`, move with the group of that tool.
- The GoReleaser of `flake.nix` comes with the hashes of its four archives,
  which Renovate does not compute: take them from the `checksums.txt` of the
  release, once `cosign verify-blob` checked its signature, with the identity
  of the release workflow of GoReleaser on its tag.
- `dagger.json`: then `task dagger:develop` and `task check:fmt:dagger`.
- `.github/release`: `npm install` in that directory writes the lockfile,
  `npm ci --ignore-scripts` checks it. Node moves in
  `.github/release/.node-version` and in the node image of `dagger/base.go`.
- `flake.lock`: `task nix:update`.

Read the notes of every major version, and of the tools that the tests drive,
such as lego, certbot, cert-manager and PowerDNS: a renamed option only shows
when its test runs.

## Verify and commit

Run the checks of the `verify` skill for every path changed; `task check`
covers them all. Commit each group apart, with the title that Renovate would
give it, `deps: update <group or package> to <version>`, or `security:` when
the update fixes a vulnerability; the body tells what moved and how it was
checked.

## Retire the pull requests of Renovate

Once the user pushed the commits:

- Close each pull request that a commit supersedes, with a comment that names
  the commit, and delete its branch: `gh pr close <n> --delete-branch
  --comment "Superseded: the update landed on main in <sha>."`
- Dispatch the Renovate workflow, `gh workflow run renovate.yaml`, then read
  its log, which must hold no `WARN` nor `ERROR`, and its Dependency Dashboard
  issue, which must list nothing but scheduled updates such as the lock file
  maintenance.

## Triage a vulnerability finding

The findings come from the Dependabot alerts (`gh api
'repos/enix/tsigoat/dependabot/alerts?state=open'`), from `task
security:vuln-deps` (Trivy), from `task security:govulncheck`, and from the
Vulnerabilities check of Scorecard, among the code scanning alerts.

1. Find every copy of the package and what loads it. In an npm lockfile,
   `jq '.packages | to_entries[] | select(.key | test("(^|/)<name>$"))'`
   lists them, and `inBundle` marks a copy that another package bundles,
   which moves with that package alone.
2. When a fixed version fits the constraints, take it, or raise the copy
   with `overrides` in `.github/release/package.json`.
3. When nothing loads the copy and no fixed version fits, waive the finding
   in `.trivyignore`, with the reason in a comment and an `exp:` date to look
   at it again, and dismiss the Dependabot alert as not used, with a comment
   of 280 characters at most.
4. Check a waiver against a fresh Trivy database, since the cache volume of
   the Dagger pipelines keeps its database until it expires: run the Trivy
   image of `dagger/base.go` on the repository with an empty cache, without
   then with `.trivyignore`.

govulncheck reports the vulnerable code that tsigoat can reach. Scorecard
reports every vulnerable version in its manifests, `dagger/go.mod` included,
which only the CI runs.

A waiver fixes nothing: commit it as `ci:`, which makes no release.
