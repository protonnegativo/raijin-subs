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

func TestInRangeAndKnownBad(t *testing.T) {
	for _, c := range []struct {
		v, r string
		want bool
	}{
		{"1.3.0", ">=1.3.0", true}, {"1.3.1", ">=1.3.0", true}, {"2.0.0", ">=1.3.0", true},
		{"1.2.1", ">=1.3.0", false}, {"1.2.9", ">=1.3.0", false},
		{"1.3.4", ">=1.3.0,<1.3.5", true}, {"1.3.5", ">=1.3.0,<1.3.5", false},
		{"1.3.5", "<=1.3.5", true}, {"1.3.5", ">1.3.5", false},
		{"", ">=1.3.0", false}, {"1.3.0", "", false}, {"1.3.0", "~1.3.0", false},
	} {
		if got := InRange(c.v, c.r); got != c.want {
			t.Errorf("InRange(%q, %q) = %v, want %v", c.v, c.r, got, c.want)
		}
	}
	// dnsx 1.3.x drops NXDOMAIN names from -json (projectdiscovery/dnsx#1091): known-bad although it is
	// the same major and newer than the tested 1.2.1, so Untested alone would not warn.
	if _, bad := KnownBad("dnsx", "1.3.1"); !bad || Untested("1.3.1", "1.2.1") {
		t.Error("dnsx 1.3.1 must be known-bad")
	}
	if _, bad := KnownBad("dnsx", "1.2.1"); bad {
		t.Error("dnsx 1.2.1 is not known-bad")
	}
	if _, bad := KnownBad("subfinder", "2.17.0"); bad {
		t.Error("subfinder has no known-bad range")
	}
}

// The drift job bumps engines.json only when the new dnsx passes its NXDOMAIN check. If it passes but
// is still in KnownBad, the fix has shipped: close the range in engines.go.
func TestTestedIsNotKnownBad(t *testing.T) {
	m, err := Tested()
	if err != nil {
		t.Fatal(err)
	}
	for name, e := range m {
		if b, bad := KnownBad(name, e.Version); bad {
			t.Errorf("engines.json tests %s %s, which KnownBad lists as %s; if it is fixed, close the range in engines.go", name, e.Version, b.Range)
		}
	}
}
