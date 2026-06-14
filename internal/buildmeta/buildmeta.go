package buildmeta

import (
	"fmt"
	"runtime"
	"strings"
)

// Version, Commit, and BuildDate are injected by ldflags at build time.
// They fall back to safe local defaults when built without ldflags.
var (
	Version   = "dev"
	Commit    = "local"
	BuildDate = "local"
)

// Info captures the build metadata shown by the CLI and UI.
type Info struct {
	Version   string
	Commit    string
	BuildDate string
	GoVersion string
	GOOS      string
	GOARCH    string
}

// Current returns the active build metadata snapshot for this binary.
func Current() Info {
	return Info{
		Version:   fallback(Version, "dev"),
		Commit:    fallback(Commit, "local"),
		BuildDate: fallback(BuildDate, "local"),
		GoVersion: runtime.Version(),
		GOOS:      runtime.GOOS,
		GOARCH:    runtime.GOARCH,
	}
}

// String renders the metadata in the same format used by cf-sync --version.
func (i Info) String() string {
	return fmt.Sprintf(
		"Version:    %s\nCommit:     %s\nBuild date: %s\nGo version: %s\nOS / arch:  %s / %s",
		i.Version, i.Commit, i.BuildDate, i.GoVersion, i.GOOS, i.GOARCH,
	)
}

func fallback(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}
