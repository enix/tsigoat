package main

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"dagger/tsigoat/internal/dagger"
)

// releaseArchives are the archives of a release, named
// tsigoat-<tag>-<suffix>.
var releaseArchives = []string{
	"darwin-amd64.tar.gz", "darwin-arm64.tar.gz",
	"freebsd-amd64.tar.gz", "freebsd-arm64.tar.gz",
	"linux-amd64.tar.gz", "linux-arm64.tar.gz", "linux-riscv64.tar.gz",
	"windows-amd64.zip", "windows-arm64.zip",
}

// releasePlatforms are the platforms of the images of a release, with what
// file(1) says of the machine of their binary.
var releasePlatforms = map[dagger.Platform]string{
	"linux/amd64":   "x86-64",
	"linux/arm64":   "ARM aarch64",
	"linux/riscv64": "RISC-V",
}

// buildConfig is the minimal configuration that the images start with: a
// zone on a webhook backend, whose SOA tsigoat answers without calling the
// endpoint.
const buildConfig = `listen: ["[::]:5353"]
admin:
  listen: "[::]:9153"
keys:
  - name: build.
    secretFile: /etc/tsigoat/build.key
backends:
  - name: hook
    type: webhook
    webhook:
      url: http://webhook.invalid/updates
zones:
  - name: example.test.
    backend: hook
    keys: [build.]
`

// TestBuild checks what a release builds, without publishing anything:
// GoReleaser checks its configuration and builds a snapshot of every
// platform; the archives of every platform are there, and the checksums
// cover and match them and the packages; the binary prints the version and
// the commit of the snapshot. Both images of every platform are built from
// the Dockerfiles of the release, as dockers_v2 lays out their context, with
// the binary of their platform; those of the platform of the engine start
// on a minimal configuration and answer a SOA query and the health check.
func (m *Tsigoat) TestBuild(ctx context.Context) (string, error) {
	snapshot := dag.Container().
		From(goreleaserImage).
		WithEnvVariable("GOTOOLCHAIN", "auto").
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
goreleaser check
goreleaser release --snapshot --clean --skip=docker,sign,sbom
`})
	dist := snapshot.Directory("/src/dist")
	var report strings.Builder

	commit, err := snapshot.WithExec([]string{"git", "rev-parse", "HEAD"}).Stdout(ctx)
	if err != nil {
		return "", err
	}
	commit = strings.TrimSpace(commit)
	var metadata struct {
		Tag     string `json:"tag"`
		Version string `json:"version"`
	}
	if err := readJSON(ctx, dist.File("metadata.json"), &metadata); err != nil {
		return "", err
	}

	entries, err := dist.Entries(ctx)
	if err != nil {
		return "", err
	}
	for _, suffix := range releaseArchives {
		if name := fmt.Sprintf("tsigoat-%s-%s", metadata.Tag, suffix); !slices.Contains(entries, name) {
			return "", fmt.Errorf("the snapshot lacks %s", name)
		}
	}
	fmt.Fprintf(&report, "archives: the %d of %s\n", len(releaseArchives), metadata.Tag)

	checked, err := dag.Container().
		From(alpineImage).
		WithMountedDirectory("/dist", dist).
		WithWorkdir("/dist").
		WithExec([]string{"sh", "-euc", `
for file in tsigoat-*.tar.gz tsigoat-*.zip *.deb *.rpm; do
  grep -q "  $file\$" checksums.txt || { echo "checksums.txt lacks $file"; exit 1; }
done
sha256sum -c checksums.txt | wc -l
`}).
		Stdout(ctx)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(&report, "checksums: %s files, archives and packages\n", strings.TrimSpace(checked))

	var artifacts []struct {
		Type   string `json:"type"`
		Goos   string `json:"goos"`
		Goarch string `json:"goarch"`
		Path   string `json:"path"`
	}
	if err := readJSON(ctx, dist.File("artifacts.json"), &artifacts); err != nil {
		return "", err
	}
	binaries := map[dagger.Platform]*dagger.File{}
	for _, artifact := range artifacts {
		if artifact.Type == "Binary" && artifact.Goos == "linux" {
			binaries[dagger.Platform("linux/"+artifact.Goarch)] = snapshot.File("/src/" + artifact.Path)
		}
	}
	engine, err := dag.DefaultPlatform(ctx)
	if err != nil {
		return "", err
	}
	if binaries[engine] == nil {
		return "", fmt.Errorf("the snapshot holds no binary for %s, the platform of the engine", engine)
	}

	version, err := dag.Container().
		From(alpineImage).
		WithMountedFile("/tsigoat", binaries[engine]).
		WithExec([]string{"/tsigoat", "version"}).
		Stdout(ctx)
	if err != nil {
		return "", err
	}
	if !strings.Contains(version, metadata.Version) || !strings.Contains(version, commit) {
		return "", fmt.Errorf("tsigoat version does not print the version %s and the commit %s of the snapshot:\n%s",
			metadata.Version, commit, version)
	}
	fmt.Fprintf(&report, "version: %s, commit %s\n", metadata.Version, commit[:12])

	key := dag.Container().
		From(alpineImage).
		WithExec([]string{"sh", "-euc", "head -c 32 /dev/urandom | base64 > /build.key"}).
		File("/build.key")
	machines := dag.Container().
		From(alpineImage).
		WithExec([]string{"apk", "add", "--no-cache", "file"})
	for _, variant := range []string{"scratch", "busybox"} {
		for _, platform := range sortedPlatforms() {
			binary := binaries[platform]
			if binary == nil {
				return "", fmt.Errorf("the snapshot holds no binary for %s", platform)
			}
			// Dagger reports the platform of the engine for an image built
			// FROM scratch: the machine of the binary tells the platform.
			image := dag.Directory().
				WithFile(string(platform)+"/tsigoat", binary).
				WithFile("Dockerfile", m.Source.File("build/Dockerfile."+variant)).
				DockerBuild(dagger.DirectoryDockerBuildOpts{Platform: platform})
			if user, err := image.User(ctx); err != nil || user != "65534:65534" {
				return "", fmt.Errorf("the %s image for %s runs as %q, not 65534:65534 (%v)", variant, platform, user, err)
			}
			machines = machines.WithMountedDirectory(fmt.Sprintf("/images/%s/%s", variant, platform), image.Rootfs())
			if platform == engine {
				if err := startImage(ctx, image, key); err != nil {
					return "", fmt.Errorf("starting the %s image: %w", variant, err)
				}
				fmt.Fprintf(&report, "%s image of %s: answers SOA and /healthz\n", variant, platform)
			}
		}
	}
	for _, variant := range []string{"scratch", "busybox"} {
		for _, platform := range sortedPlatforms() {
			described, err := machines.WithExec([]string{"file", "-b", fmt.Sprintf("/images/%s/%s/tsigoat", variant, platform)}).Stdout(ctx)
			if err != nil {
				return "", err
			}
			if !strings.Contains(described, releasePlatforms[platform]) {
				return "", fmt.Errorf("the binary of the %s image for %s is %s", variant, platform, strings.TrimSpace(described))
			}
		}
	}
	fmt.Fprintf(&report, "images: scratch and busybox for %d platforms, each with the binary of its machine\n", len(releasePlatforms))
	return report.String(), nil
}

// startImage starts an image of tsigoat on the minimal configuration, and
// checks that it answers the SOA query of its zone, over UDP and TCP, and the
// health check.
func startImage(ctx context.Context, image *dagger.Container, key *dagger.File) error {
	server := image.
		WithNewFile("/etc/tsigoat/config.yaml", buildConfig).
		WithFile("/etc/tsigoat/build.key", key).
		WithExposedPort(5353, dagger.ContainerWithExposedPortOpts{Protocol: dagger.NetworkProtocolTcp}).
		WithExposedPort(5353, dagger.ContainerWithExposedPortOpts{Protocol: dagger.NetworkProtocolUdp}).
		WithExposedPort(9153).
		AsService(dagger.ContainerAsServiceOpts{UseEntrypoint: true})
	_, err := dag.Container().
		From(alpineImage).
		WithExec([]string{"apk", "add", "--no-cache", "bind-tools", "curl"}).
		WithServiceBinding("tsigoat", server).
		WithExec([]string{"sh", "-euc", `
dig @tsigoat -p 5353 example.test SOA +short +notcp | grep -q 'hostmaster.example.test.'
dig @tsigoat -p 5353 example.test SOA +short +tcp | grep -q 'hostmaster.example.test.'
curl -fsS http://tsigoat:9153/healthz
`}).
		Sync(ctx)
	return err
}

// sortedPlatforms returns the platforms of the images in a stable order.
func sortedPlatforms() []dagger.Platform {
	platforms := make([]dagger.Platform, 0, len(releasePlatforms))
	for platform := range releasePlatforms {
		platforms = append(platforms, platform)
	}
	slices.Sort(platforms)
	return platforms
}

// readJSON decodes a JSON file.
func readJSON(ctx context.Context, file *dagger.File, value any) error {
	contents, err := file.Contents(ctx)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(contents), value)
}
