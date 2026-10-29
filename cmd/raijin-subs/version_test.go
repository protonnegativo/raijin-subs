package main

import (
	"bytes"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-subs/internal/engines"
)

func TestBuildVersion(t *testing.T) {
	rev := []debug.BuildSetting{{Key: "vcs.revision", Value: "0123456789abcdef0123"}, {Key: "vcs.modified", Value: "true"}}
	for _, c := range []struct {
		bi   *debug.BuildInfo
		ok   bool
		want string
	}{
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}, true, "v0.1.3"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}, Settings: rev}, true, "dev-0123456789ab+dirty"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20260101000000-0123456789ab"}, Settings: rev[:1]}, true, "dev-0123456789ab"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, true, "dev"},
		{nil, false, "dev"},
	} {
		if got := buildVersion(c.bi, c.ok); got != c.want {
			t.Errorf("buildVersion(%+v) = %q, want %q", c.bi, got, c.want)
		}
	}
}

func TestVersionFlag(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--version"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	tested, _ := engines.Tested()
	want := "raijin-subs " + version + " (tested with dnsx " + tested["dnsx"].Version + ", subfinder " + tested["subfinder"].Version + ")\n"
	if out.String() != want {
		t.Errorf("--version = %q, want %q", out.String(), want)
	}
	if !regexp.MustCompile(`^raijin-subs \S+ \(tested with dnsx \d+\.\d+\.\d+, subfinder \d+\.\d+\.\d+\)$`).MatchString(strings.TrimSpace(out.String())) {
		t.Errorf("--version format: %q", out.String())
	}
}

func TestReleaseVersionWinsOverBuildInfo(t *testing.T) {
	old := releaseVersion
	t.Cleanup(func() { releaseVersion = old })
	releaseVersion = "v9.9.9"
	if got := buildVersion(&debug.BuildInfo{Main: debug.Module{Version: "v1.0.0"}}, true); got != "v9.9.9" {
		t.Errorf("buildVersion = %q, want v9.9.9", got)
	}
	if got := buildVersion(nil, false); got != "v9.9.9" {
		t.Errorf("buildVersion without build info = %q, want v9.9.9", got)
	}
}
