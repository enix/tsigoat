package main

import (
	"context"

	"dagger/tsigoat/internal/dagger"
)

// releaseScript runs semantic-release in dry runs on a history made for it:
// v0.1.0 on release, then a feature, a breaking fix, a dependency bump and a
// chore on main. The GitHub plugin, which needs a token and the API, stays
// out; the rest of .releaserc.mjs runs as in the Tag a release workflow.
const releaseScript = `
sr=/src/.github/release/node_modules/.bin/semantic-release
work=/tmp/work
git config --global user.name tsigoat
git config --global user.email tsigoat@example.test
git config --global init.defaultBranch main
git init -q --bare /tmp/origin.git
git init -q "$work"
mkdir -p "$work/.github/release"
cp /src/.github/release/tag-a-release.mjs "$work/.github/release/"
cat > "$work/.releaserc.mjs" <<'EOF'
import config from "/src/.releaserc.mjs";
export default {
  ...config,
  plugins: config.plugins.filter((p) => (Array.isArray(p) ? p[0] : p) !== "@semantic-release/github"),
};
EOF
cd "$work"
git add -A
git commit -q -m "chore: start"
git tag v0.1.0
git commit -q --allow-empty -m "feat(policy): grant a key the names of a certificate"
git commit -q --allow-empty -m "fix!: refuse the updates of the apex"
git commit -q --allow-empty -m "deps: update module example.test/x to v1.2.3"
git commit -q --allow-empty -m "chore: leave this out"
git remote add origin file:///tmp/origin.git
git push -q origin main v0.1.0
git push -q origin v0.1.0:refs/heads/release

# expect BRANCH TAG PRERELEASE: the dry run on BRANCH tags TAG.
expect() {
  git checkout -q "$1"
  : > /tmp/output
  : > /tmp/summary
  if ! GITHUB_OUTPUT=/tmp/output GITHUB_STEP_SUMMARY=/tmp/summary "$sr" --dry-run > /tmp/log 2>&1; then
    cat /tmp/log
    exit 1
  fi
  if ! grep -qx "tag=$2" /tmp/output || ! grep -qx "prerelease=$3" /tmp/output; then
    cat /tmp/log /tmp/output
    echo "semantic-release on $1 should tag $2, prerelease=$3"
    exit 1
  fi
  echo "$1: $2"
}

expect main v0.2.0-rc.1 true
git checkout -q release
git merge -q --ff-only main
git push -q origin release
expect release v0.2.0 false

# The sections of the notes, in the order of .releaserc.mjs, without the
# chore.
sections=$(grep '^### ' /tmp/summary | tr '\n' '|')
if [ "$sections" != "### ⚠ BREAKING CHANGES|### Features|### Bug Fixes|### Dependencies|" ]; then
  cat /tmp/summary
  echo "unexpected sections: $sections"
  exit 1
fi
if grep -q "leave this out" /tmp/summary; then
  cat /tmp/summary
  echo "the notes hold the chore"
  exit 1
fi

# The Slack message of the release, from those notes.
node -e '
const fs = require("node:fs");
const notes = fs.readFileSync("/tmp/summary", "utf8").split("\n").slice(2).join("\n");
fs.writeFileSync("/tmp/release.json", JSON.stringify({ tagName: "v0.2.0", isPrerelease: false, body: notes }));
'
node /src/.github/release/announce.mjs --dry-run /tmp/release.json > /tmp/slack
grep -q 'Current version is \*0.2.0\*' /tmp/slack
grep -q 'releases/tag/v0.2.0|v0.2.0' /tmp/slack
echo "slack: announces v0.2.0"
`

// TestRelease checks the release configuration: semantic-release computes
// the versions and the notes that .releaserc.mjs promises, with the packages
// that .github/release pins, and the Slack announcement renders.
func (m *Tsigoat) TestRelease(ctx context.Context) (string, error) {
	return dag.Container().
		From(nodeImage).
		WithExec([]string{"apk", "add", "--no-cache", "git"}).
		WithDirectory("/src", m.Source, dagger.ContainerWithDirectoryOpts{
			Include: []string{".releaserc.mjs", ".github/release/**"},
			Exclude: []string{".github/release/node_modules"},
		}).
		WithMountedCache("/root/.npm", dag.CacheVolume("npm")).
		WithExec([]string{"npm", "ci", "--prefix", "/src/.github/release", "--ignore-scripts", "--no-audit", "--no-fund"}).
		WithExec([]string{"sh", "-euc", releaseScript}).
		Stdout(ctx)
}
