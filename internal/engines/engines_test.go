package engines

import "testing"

func TestTestedHasEveryEngine(t *testing.T) {
	m, err := Tested()
	if err != nil {
		t.Fatal(err)
	}
	for name := range VersionArgs {
		e, ok := m[name]
		if !ok || parts(e.Version) == nil || e.Go == "" {
			t.Errorf("engines.json entry for %s: %+v", name, e)
		}
	}
}

func TestParseVersion(t *testing.T) {
	for out, want := range map[string]string{
		// subfinder -version -duc (stderr)
		"[\x1b[34mINF\x1b[0m] Current Version: v2.6.7\n[\x1b[34mINF\x1b[0m] Subfinder Config Directory: /root/.config/subfinder\n": "2.6.7",
		// dnsx -version -duc (stderr, after the banner)
		"\n      _             __  __\n   __| | _ __   ___ \\ \\/ /\n\n\t\tprojectdiscovery.io\n\n[\x1b[34mINF\x1b[0m] Current Version: 1.2.1\n": "1.2.1",
		"flag provided but not defined: -version": "",
	} {
		if got := ParseVersion(out); got != want {
			t.Errorf("ParseVersion(%q) = %q, want %q", out, got, want)
		}
	}
}

func TestUntested(t *testing.T) {
	for _, c := range []struct {
		installed, tested string
		want              bool
	}{
		{"2.6.7", "2.6.7", false},
		{"2.6.8", "2.6.7", false},
		{"2.10.0", "2.6.7", false},
		{"2.6.6", "2.6.7", true},
		{"2.5.9", "2.6.7", true},
		{"3.0.0", "2.6.7", true},
		{"1.9.9", "2.6.7", true},
		{"", "2.6.7", false},
		{"x", "2.6.7", false},
	} {
		if got := Untested(c.installed, c.tested); got != c.want {
			t.Errorf("Untested(%q, %q) = %v, want %v", c.installed, c.tested, got, c.want)
		}
	}
}
