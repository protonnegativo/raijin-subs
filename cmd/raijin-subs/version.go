package main

import (
	"regexp"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-subs/internal/engines"
)

// releaseVersion is set at link time by release builds (-ldflags "-X main.releaseVersion=v1.2.3"). It has
// to be an uninitialized string: -X is ignored for a variable initialized with a function call.
var releaseVersion string

// version is the release this binary was built at: releaseVersion for a release build, the module version
// for go install ...@vX.Y.Z or @latest, or "dev" with the VCS revision for a local go build.
var version = buildVersion(debug.ReadBuildInfo())

// pseudo matches the timestamp-revision part of a pseudo-version (v0.0.0-20260101000000-0123456789ab),
// which a go build of an untagged commit gets.
var pseudo = regexp.MustCompile(`\d{14}-[0-9a-f]{12}`)

// buildVersion returns releaseVersion when it is set, otherwise the module version from the build info
// when it is a real release, and otherwise "dev", plus "-<revision>" (12 characters) and "+dirty" when
// the build settings carry them.
func buildVersion(bi *debug.BuildInfo, ok bool) string {
	if releaseVersion != "" {
		return releaseVersion
	}
	if !ok || bi == nil {
		return "dev"
	}
	if v := bi.Main.Version; v != "" && v != "(devel)" && !pseudo.MatchString(v) && !strings.HasSuffix(v, "+dirty") {
		return v
	}
	v := "dev"
	var dirty bool
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) > 12 {
				s.Value = s.Value[:12]
			}
			v += "-" + s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if dirty {
		v += "+dirty"
	}
	return v
}

// versionLine is what --version prints: the release and the engine versions it was tested with.
func versionLine() string {
	line := "raijin-subs " + version
	tested, err := engines.Tested()
	if err != nil || len(tested) == 0 {
		return line
	}
	names := make([]string, 0, len(tested))
	for n := range tested {
		names = append(names, n)
	}
	sort.Strings(names)
	for i, n := range names {
		names[i] = n + " " + tested[n].Version
	}
	return line + " (tested with " + strings.Join(names, ", ") + ")"
}
