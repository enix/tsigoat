package product

import (
	"runtime"
)

var (
	version      = ""
	buildTime    = ""
	gitCommit    = ""
	gitTreeState = ""
)

type buildInfo struct {
	Version      string
	BuildTime    string
	GitCommit    string
	GitTreeState string
	Runtime      string
	Os           string
	Arch         string
}

func BuildInfo() buildInfo {
	info := buildInfo{
		Runtime: runtime.Version(),
		Os:      runtime.GOOS,
		Arch:    runtime.GOARCH,
	}

	if len(version) > 0 {
		info.Version = version
	} else {
		info.Version = "unknown"
	}

	if len(buildTime) > 0 {
		info.BuildTime = buildTime
	} else {
		info.BuildTime = "unknown"
	}

	if len(gitCommit) > 0 {
		info.GitCommit = gitCommit
	} else {
		info.GitCommit = "unknown"
	}

	if len(gitTreeState) > 0 {
		info.GitTreeState = gitTreeState
	} else {
		info.GitTreeState = "unknown"
	}

	return info
}

func VariadicBuildInfo() []interface{} {
	info := BuildInfo()
	return []interface{}{
		"version", info.Version,
		"built", info.BuildTime,
		"commit", info.GitCommit,
		"state", info.GitTreeState,
		"runtime", info.Runtime,
		"os", info.Os,
		"arch", info.Arch,
	}
}
