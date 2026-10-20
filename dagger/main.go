// Tsigoat holds the sandboxed QA and CI pipelines of tsigoat.
//
// Each exported method of the Tsigoat struct is a Dagger function. Because
// dagger.json lives at the repository root, `dagger call <function>` finds
// the module from any directory of the checkout. Taskfile.yml wraps these
// calls under task names (lint:go, test:unit, ...).
package main

import (
	"dagger/tsigoat/internal/dagger"
)

// Tsigoat holds the source tree shared by every function.
type Tsigoat struct {
	// +private
	Source *dagger.Directory
}

// New builds the module instance from the working tree. Build outputs, local
// state and VCS data are excluded so that they do not bust the cache.
func New(
	// +defaultPath="/"
	// +ignore=["dist/", ".git/", "tmp/", "docs/", "dagger/", ".keyring/", "kubeconfig.yaml"]
	source *dagger.Directory,
) *Tsigoat {
	return &Tsigoat{Source: source}
}
