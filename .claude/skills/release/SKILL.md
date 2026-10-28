---
name: release
description: Cut a release candidate of tsigoat from main, or a stable version from the release branch, follow its workflows to the publication, recover from a failed run, and verify what the release published. Use when asked to release, tag or publish a version or a release candidate, or to check a published one.
---

# Release tsigoat

`CONTRIBUTING.md` (Releases) describes the release model and the recovery of
a failed release; `SECURITY.md` (Verifying releases) gives the commands that
check a published one. Read both first: this skill is the procedure around
them.

Each step that pushes, tags, dispatches or reruns a workflow, or deletes a
release, needs the agreement of the user, given in the conversation for that
step. Never approve a deployment of the `release` environment: its reviewers
do.

## Before tagging

- Every workflow of the commit to release passed: `gh run list --commit
  <sha>`. A red Security run often comes from an advisory published since the
  last run: the release gates would fail on it too.
- The last Nightly passed: the release does not require it, but its
  acceptance test and fuzzing run nowhere else.
- For a stable version, `release` first moves forward to the commit that a
  candidate tested, as CONTRIBUTING shows.

## Tag

1. Dry run: `gh workflow run tag.yaml --ref <branch> -f dry-run=true`. Its
   log gives the version, after `The next release version is`, and the notes,
   after `Release note for version`. Show both to the user.
2. Once the user agrees: `gh workflow run tag.yaml --ref <branch>`.
3. Check the tag (`git fetch --tags`), on the expected commit; the draft
   release named after it, with its notes, a prerelease for a candidate
   (`gh release view <tag> --json isDraft,isPrerelease,body`); and the run of
   the release workflow on the tag, which Tag a release dispatched: a tag
   pushed with the `GITHUB_TOKEN` starts no workflow.

## Follow the release

The run passes its quality gates, then two jobs deploy to the `release`
environment, each once its reviewers approve it: `Build, push and sign`
(GoReleaser), then `Chart publish and sign`. Last, `Publish and announce`
checks that the draft holds every file of `checksums.txt`, publishes it, and
announces it on Slack.

Watch the run in the background, and tell the user, with the link of the run,
when a deployment waits for approval, and when a job fails:

```sh
gh api repos/enix/tsigoat/actions/runs/<id>/pending_deployments --jq length
gh run view <id> --json status,jobs
```

## When a job fails

1. Read the failed step: `gh api repos/enix/tsigoat/actions/jobs/<job>/logs`.
2. Find what left the repository: the files of the draft (`gh release view
   <tag> --json assets`), the images of the version on ghcr.io, quay.io and
   docker.io, and the chart (`skopeo inspect --raw
   docker://<repository>:<version>` on each).
3. A transient failure: run the failed jobs again on the same tag, `gh run
   rerun <id> --failed`. GoReleaser replaces the files of the draft and pushes
   the images again; the deployments wait for approval again.
4. A failure that needs a change of the repository, while nothing left: as
   CONTRIBUTING says, delete the draft, the tag and its semantic-release note,
   fix `main`, and dispatch Tag a release again, which computes the same
   version. Never move the tag alone: semantic-release reads the channel of a
   version from its note, `refs/notes/semantic-release-<tag>`, on the tagged
   commit, and computes the version of a tag without one again.
5. Once an image left, the version is out: the fix takes the next version.

A signature that fails with `409 createLogEntryConflict` from Rekor comes
from a slow log: it wrote the entry, answered an error, and the client sent
the entry again. cosign 3.1 and later read the entry that Rekor holds; an
older cosign fails until the log answers in time again.

## Verify the release

Once the release is published, run the commands of SECURITY.md with the
identity of its tag, then check:

- the release: published, a prerelease for a candidate and `latest` for a
  stable version; its files, the archives of every build of `.goreleaser.yaml`,
  the deb and rpm packages, `checksums.txt` and its bundle;
- the SBOM attestation of every platform of both images, on the digest of
  each platform;
- the `latest` and `busybox` tags of the images, which a stable version moves
  and a candidate leaves where they are;
- the chart at `oci://quay.io/enix/charts/tsigoat`, signed, with the digests
  of the images in `image.digests`, and its entry in the index of
  charts.enix.io;
- for a stable version, the module on the Go proxy and pkg.go.dev.

Then tell the user what was checked, and what was not.
