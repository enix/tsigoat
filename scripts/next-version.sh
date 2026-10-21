#!/usr/bin/env bash
# Prints the version of the next release of tsigoat, which svu computes from
# the Conventional Commits since the last release: a feature makes a minor
# version, a breaking change too while tsigoat is in 0.x, and anything else
# a patch. With --rc, prints the next release candidate of that version,
# vX.Y.Z-rc.N.
#
# svu counts from the last tag, release candidates included, and would bump
# again the version that they prepare: it runs on a bare copy of the
# repository, without them. Fails when nothing came since the last release.
set -euo pipefail

SVU_VERSION=v3.4.1

rc=false
case "${1:-}" in
  --rc) rc=true ;;
  "") ;;
  *)
    echo "usage: $0 [--rc]" >&2
    exit 2
    ;;
esac

root=$(git rev-parse --show-toplevel)
head=$(git -C "$root" rev-parse HEAD)
copy=$(mktemp -d)
trap 'rm -rf "$copy"' EXIT
git clone --quiet --bare "$root" "$copy"
git -C "$copy" update-ref --no-deref HEAD "$head"
mapfile -t candidates < <(git -C "$copy" tag --list 'v*-*')
if [ "${#candidates[@]}" -gt 0 ]; then
  git -C "$copy" tag --delete "${candidates[@]}" >/dev/null
fi

if last=$(git -C "$copy" describe --tags --abbrev=0 --match 'v*' 2>/dev/null) &&
  [ "$(git -C "$copy" rev-list --count "$last..HEAD")" -eq 0 ]; then
  echo "nothing to release since $last" >&2
  exit 1
fi

version=$(cd "$copy" && go run "github.com/caarlos0/svu/v3@${SVU_VERSION}" next --v0 --always)
if [ "$rc" = true ]; then
  n=0
  for tag in "${candidates[@]}"; do
    number=${tag#"$version"-rc.}
    if [ "$number" != "$tag" ] && [[ "$number" =~ ^[0-9]+$ ]] && [ "$number" -gt "$n" ]; then
      n=$number
    fi
  done
  version="$version-rc.$((n + 1))"
fi
echo "$version"
