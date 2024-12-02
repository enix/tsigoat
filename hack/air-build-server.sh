#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

export CGO_ENABLED=0
export GO111MODULE=on
export GOFLAGS="-mod=vendor"

MODULE=$(go list -m)

LDFLAGS=()
LDFLAGS+=" -X ${MODULE}/internal/product.version=$(git describe --tags --always --dirty)"
LDFLAGS+=" -X ${MODULE}/internal/product.buildTime=$(date --iso-8601=seconds)"
LDFLAGS+=" -X ${MODULE}/internal/product.gitCommit=$(git rev-parse HEAD)"
LDFLAGS+=" -X ${MODULE}/internal/product.gitTreeState=$(test -n "`git status --porcelain`" && echo "dirty" || echo "clean")"

go build \
    -ldflags "${LDFLAGS[*]}" \
    -o ./tmp/cmd \
    ./cmd
