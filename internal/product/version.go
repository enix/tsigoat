package product

import (
	"runtime"
)

// Unknown is reported for build metadata that was not injected at link time.
const Unknown = "unknown"

// Build metadata, set at link time with -ldflags -X.
//
//nolint:gochecknoglobals // the linker can only set package-level variables
var (
	version      = ""
	buildTime    = ""
	gitCommit    = ""
	gitTreeState = ""
)

// Info describes the running binary.
type Info struct {
	Version      string
	BuildTime    string
	GitCommit    string
	GitTreeState string
	Runtime      string
	Os           string
	Arch         string
}

// BuildInfo returns the metadata of the running binary.
func BuildInfo() Info {
	return Info{
		Version:      valueOrUnknown(version),
		BuildTime:    valueOrUnknown(buildTime),
		GitCommit:    valueOrUnknown(gitCommit),
		GitTreeState: valueOrUnknown(gitTreeState),
		Runtime:      runtime.Version(),
		Os:           runtime.GOOS,
		Arch:         runtime.GOARCH,
	}
}

// VariadicBuildInfo returns the build metadata as alternating keys and values,
// ready to be passed to a structured logger.
func VariadicBuildInfo() []any {
	info := BuildInfo()
	return []any{
		"version", info.Version,
		"built", info.BuildTime,
		"commit", info.GitCommit,
		"state", info.GitTreeState,
		"runtime", info.Runtime,
		"os", info.Os,
		"arch", info.Arch,
	}
}

func valueOrUnknown(value string) string {
	if value == "" {
		return Unknown
	}
	return value
}
