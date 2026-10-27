package main

import (
	"context"

	"dagger/tsigoat/internal/dagger"
)

// packageChecks run after the installation of a package: the binary runs,
// the system user owns the group of /etc/tsigoat, and the unit, the sysusers
// file and the example configuration are in place.
const packageChecks = `
tsigoat version
getent passwd tsigoat
test "$(stat -c %U:%G:%a /etc/tsigoat)" = root:tsigoat:750
test -f /usr/lib/systemd/system/tsigoat.service
test -f /usr/lib/sysusers.d/tsigoat.conf
test -f /usr/share/doc/tsigoat/examples/config.yaml
`

// TestPackages builds the deb and rpm packages of the Linux platforms with
// GoReleaser, as a snapshot, then installs the package of the platform of
// the engine on Debian and on AlmaLinux, checks it, and removes it.
func (m *Tsigoat) TestPackages(ctx context.Context) (string, error) {
	dist := dag.Container().
		From(goreleaserImage).
		WithEnvVariable("GOTOOLCHAIN", "auto").
		WithEnvVariable("GORELEASER_LOCAL_PLATFORM", "1").
		WithMountedCache("/go/pkg/mod", dag.CacheVolume("go-mod")).
		WithMountedCache("/root/.cache/go-build", dag.CacheVolume("go-build")).
		WithDirectory("/src", m.Source).
		WithWorkdir("/src").
		// The source comes without its history: a repository of one commit
		// gives GoReleaser the commit that it reads, and a remote, without
		// which it reads no git information at all.
		WithExec([]string{"sh", "-euc", `
git init -q
git add -A
git -c user.name=tsigoat -c user.email=tsigoat@example.test commit -q -m snapshot
git remote add origin https://github.com/enix/tsigoat.git
goreleaser release --snapshot --clean --skip=docker,sign,sbom
`}).
		Directory("/src/dist")

	debian, err := dag.Container().
		From(debianImage).
		WithDirectory("/dist", dist, dagger.ContainerWithDirectoryOpts{Include: []string{"*.deb"}}).
		WithExec([]string{"sh", "-euc", `
# The slim image leaves out /usr/share/doc, which a host keeps.
rm -f /etc/dpkg/dpkg.cfg.d/docker
apt-get install -y /dist/tsigoat_*_$(dpkg --print-architecture).deb
` + packageChecks + `
apt-get remove -y tsigoat
test ! -e /usr/bin/tsigoat
`}).
		Stdout(ctx)
	if err != nil {
		return "", err
	}

	almalinux, err := dag.Container().
		From(almalinuxImage).
		WithDirectory("/dist", dist, dagger.ContainerWithDirectoryOpts{Include: []string{"*.rpm"}}).
		WithExec([]string{"sh", "-euc", `
dnf install -y --disablerepo='*' /dist/tsigoat-*.$(uname -m).rpm
` + packageChecks + `
dnf remove -y --disablerepo='*' tsigoat
test ! -e /usr/bin/tsigoat
`}).
		Stdout(ctx)
	if err != nil {
		return "", err
	}
	return debian + almalinux, nil
}
