package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func scopeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "scope.txt")
	if err := os.WriteFile(p, []byte("*.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type output struct {
	Summary  string
	Findings []struct {
		ID, Severity string
		Locations    []string
	}
	Groups []struct {
		ID, Status, Wildcard string
		Locations            []string
	}
	Errors []struct{ Kind, Hint string }
	Raw    string
}

func TestNoBannerByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if errb.Len() != 0 {
		t.Errorf("stderr should be empty without --banner, got %q", errb.String())
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v", err)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--banner", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(errb.String(), "TGT-LOCK") || !strings.Contains(errb.String(), "raijin-subs v"+version) {
		t.Errorf("banner missing or without the version: %q", errb.String())
	}
	if strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner leaked into stdout")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}

func TestCompactByDefault(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("default JSON should be one line, got %d lines", n)
	}
	var pretty bytes.Buffer
	if code := run([]string{"--pretty", "--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &pretty, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(pretty.String(), "\n  \"tool\"") {
		t.Errorf("--pretty should indent: %q", pretty.String())
	}
	var a, b map[string]any
	if json.Unmarshal(out.Bytes(), &a) != nil || json.Unmarshal(pretty.Bytes(), &b) != nil || len(a) != len(b) {
		t.Error("compact and pretty should carry the same fields")
	}
	want := `"summary":"16 names, 12 resolve, 5 findings (1 high, 2 medium, 2 low), 6 groups, wildcard *.wild.example.com"`
	if !strings.Contains(out.String(), want) {
		t.Errorf("summary: %s", out.String())
	}
}

func TestInputCanBeSplitAcrossFiles(t *testing.T) {
	b, err := os.ReadFile("../../testdata/sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	var sf, dx []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if strings.Contains(l, `"status_code"`) {
			dx = append(dx, l)
		} else {
			sf = append(sf, l)
		}
	}
	os.WriteFile(filepath.Join(dir, "sf.jsonl"), []byte(strings.Join(sf, "\n")), 0o600)
	os.WriteFile(filepath.Join(dir, "dnsx.jsonl"), []byte(strings.Join(dx, "\n")), 0o600)
	var whole, split, errb bytes.Buffer
	run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl"}, &whole, &errb)
	run([]string{"--scope", scopeFile(t), "--input", filepath.Join(dir, "sf.jsonl"), "--input", filepath.Join(dir, "dnsx.jsonl")}, &split, &errb)
	var a, c output
	json.Unmarshal(whole.Bytes(), &a)
	json.Unmarshal(split.Bytes(), &c)
	if a.Summary != c.Summary || len(a.Findings) != len(c.Findings) || len(a.Groups) != len(c.Groups) {
		t.Errorf("one combined file and two files should give the same result:\n%s\n%s", whole.String(), split.String())
	}

	// subfinder output alone: every name is listed, as UNCHECKED
	var only bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", filepath.Join(dir, "sf.jsonl")}, &only, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	var o output
	json.Unmarshal(only.Bytes(), &o)
	if len(o.Groups) != 1 || o.Groups[0].Status != "UNCHECKED" || len(o.Groups[0].Locations) != 16 || !strings.Contains(o.Summary, "not resolved") {
		t.Errorf("subfinder-only replay: %s", only.String())
	}
}

func TestMissingEngineExitsTwoWithHint(t *testing.T) {
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-d", "example.com", "--subfinder", "/nonexistent/subfinder"}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var v output
	if err := json.Unmarshal(out.Bytes(), &v); err != nil || len(v.Errors) != 1 || v.Errors[0].Kind != "missing_engine" || !strings.Contains(v.Errors[0].Hint, "--subfinder") {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestUsageErrorsExitOne(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--input", "../../testdata/sample.jsonl"}, &out, &errb); code != 1 {
		t.Errorf("no --scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "-d", "example.org"}, &out, &errb); code != 1 {
		t.Errorf("no root in scope: exit %d, want 1", code)
	}
	if code := run([]string{"--scope", scopeFile(t), "--nope"}, &out, &errb); code != 1 {
		t.Errorf("unknown flag: exit %d, want 1", code)
	}
}

// fakeEngines writes shell scripts that answer like subfinder and dnsx, so the live path runs offline.
// The fake dnsx answers 192.0.2.50 for every name under w.example.com, the probe included.
func fakeEngines(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	sf := `#!/bin/sh
[ "$1" = -version ] && { echo "[INF] Current Version: v2.6.7" >&2; exit 0; }
for n in www api dev a.w b.w c.w d.w e.w; do echo "{\"host\":\"$n.example.com\",\"input\":\"example.com\",\"sources\":[\"crtsh\"]}"; done
echo '{"host":"x.example.org","input":"example.com","sources":["crtsh"]}'
`
	dx := `#!/bin/sh
[ "$1" = -version ] && { echo "[INF] Current Version: 1.2.1" >&2; exit 0; }
while [ "$1" != "-l" ]; do shift; done
while read -r n; do
  case "$n" in
    *.w.example.com) echo "{\"host\":\"$n\",\"a\":[\"192.0.2.50\"],\"status_code\":\"NOERROR\"}" ;;
    dev.example.com) echo "{\"host\":\"$n\",\"a\":[\"10.0.0.8\"],\"status_code\":\"NOERROR\"}" ;;
    *.example.org) echo "out of scope name sent to dnsx: $n" >&2; exit 1 ;;
    *) echo "{\"host\":\"$n\",\"a\":[\"192.0.2.1\"],\"status_code\":\"NOERROR\"}" ;;
  esac
done < "$2"
`
	for name, body := range map[string]string{"subfinder": sf, "dnsx": dx} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, "subfinder"), filepath.Join(dir, "dnsx")
}

func TestLiveRunWithWildcardProbeAndReplay(t *testing.T) {
	sf, dx := fakeEngines(t)
	raw := filepath.Join(t.TempDir(), "raw.jsonl")
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-d", "example.com", "-d", "example.org", "--subfinder", sf, "--dnsx", dx, "--raw", raw}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, out.String(), errb.String())
	}
	var v output
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Errors) != 0 || v.Raw != raw {
		t.Fatalf("errors or raw: %s", out.String())
	}
	want := "8 names, 8 resolve, 1 findings (1 medium), 2 groups, wildcard *.w.example.com"
	if v.Summary != want {
		t.Errorf("summary %q, want %q", v.Summary, want)
	}
	if len(v.Groups) != 2 || v.Groups[0].Wildcard != "*.w.example.com" || len(v.Groups[0].Locations) != 5 {
		t.Errorf("groups: %s", out.String())
	}
	b, _ := os.ReadFile(raw)
	if !strings.Contains(string(b), `"input":"example.com"`) || !strings.Contains(string(b), `"host":"raijin-wc-`) {
		t.Errorf("raw should hold both engines' output and the wildcard probe: %s", b)
	}

	// replaying the raw file gives the same result without running anything
	var again bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", raw, "--subfinder", "/nonexistent", "--dnsx", "/nonexistent"}, &again, &errb); code != 0 {
		t.Fatalf("replay exit %d", code)
	}
	var r output
	json.Unmarshal(again.Bytes(), &r)
	if r.Summary != v.Summary {
		t.Errorf("replay summary %q, want %q", r.Summary, v.Summary)
	}
}

func TestMissingDnsxStillListsEveryName(t *testing.T) {
	sf, _ := fakeEngines(t)
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-d", "example.com", "--subfinder", sf, "--dnsx", "/nonexistent/dnsx", "--raw", filepath.Join(t.TempDir(), "raw.jsonl")}, &out, &errb)
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	var v output
	json.Unmarshal(out.Bytes(), &v)
	if len(v.Errors) != 1 || !strings.Contains(v.Errors[0].Hint, "--dnsx") || len(v.Groups) != 1 || v.Groups[0].Status != "UNCHECKED" || len(v.Groups[0].Locations) != 8 {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestNoResolveDoesNotRunDnsx(t *testing.T) {
	sf, _ := fakeEngines(t)
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-d", "example.com", "--no-resolve", "--sources", "--subfinder", sf, "--dnsx", "/nonexistent/dnsx", "--raw", filepath.Join(t.TempDir(), "raw.jsonl")}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	var v output
	json.Unmarshal(out.Bytes(), &v)
	if len(v.Errors) != 0 || len(v.Groups) != 1 || v.Groups[0].Status != "UNCHECKED" || v.Groups[0].Locations[0] != "a.w.example.com [crtsh]" {
		t.Errorf("stdout = %s", out.String())
	}
}

func TestTableFormat(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopeFile(t), "--input", "../../testdata/sample.jsonl", "--format", "table"}, &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	s := out.String()
	for _, want := range []string{"HIGH     dangling,third-party Dangling CNAME to GitHub Pages (1)", "         docs.example.com", "group    192.0.2.50 wildcard *.wild.example.com (5)", "group    NXDOMAIN (1)"} {
		if !strings.Contains(s, want) {
			t.Errorf("table missing %q:\n%s", want, s)
		}
	}
}

// With only --scope, subfinder enumerates every domain the scope names and the apex of each wildcard,
// once; IPs, ranges and exclusions are left out, and no next hint is needed.
func TestScopeAloneEnumeratesWhatTheScopeNames(t *testing.T) {
	dir := t.TempDir()
	scopePath := filepath.Join(dir, "scope.txt")
	body := "example.com\n*.example.com\n*.example.net\nold.example.io\n!old.example.io\n10.0.0.0/30\n192.0.2.10\n"
	if err := os.WriteFile(scopePath, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	got := filepath.Join(dir, "roots.txt")
	fake := filepath.Join(dir, "subfinder")
	script := "#!/bin/sh\nwhile [ $# -gt 0 ]; do [ \"$1\" = -dL ] && cp \"$2\" " + got + "; shift; done\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	if code := run([]string{"--scope", scopePath, "--subfinder", fake, "--no-resolve", "--raw", filepath.Join(dir, "raw.jsonl")}, &out, &errb); code != 0 {
		t.Fatalf("exit %d: %s %s", code, errb.String(), out.String())
	}
	b, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(strings.Fields(string(b)), ",") != "example.com,example.net" {
		t.Errorf("subfinder got roots %q", b)
	}
	var res struct{ Next []string }
	if err := json.Unmarshal(out.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Next) != 0 {
		t.Errorf("next = %v", res.Next)
	}
}

// An older dnsx gets an engine_version warning, and a dnsx that renamed status_code gets an
// engine_format warning with its lines counted in omitted; neither changes the exit code.
func TestEngineVersionAndFormatWarnings(t *testing.T) {
	sf, dx := fakeEngines(t)
	b, err := os.ReadFile(dx)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.ReplaceAll(string(b), "Current Version: 1.2.1", "Current Version: 1.1.0")
	body = strings.ReplaceAll(body, `\"status_code\"`, `\"status\"`)
	if err := os.WriteFile(dx, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"--scope", scopeFile(t), "-d", "example.com", "--subfinder", sf, "--dnsx", dx, "--raw", filepath.Join(t.TempDir(), "raw.jsonl")}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, out.String())
	}
	var v struct {
		output
		Omitted map[string]int
	}
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
	kinds := map[string]string{}
	for _, e := range v.Errors {
		kinds[e.Kind] = e.Hint
	}
	if h := kinds["engine_version"]; !strings.HasPrefix(h, "dnsx 1.1.0 is not the tested 1.2.1") || !strings.Contains(h, "go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.1") {
		t.Errorf("engine_version: %q", h)
	}
	if h := kinds["engine_format"]; !strings.HasPrefix(h, "8 of 8 dnsx results had no host and status_code") {
		t.Errorf("engine_format: %q", h)
	}
	if v.Omitted["unparsed"] != 8 {
		t.Errorf("omitted = %v", v.Omitted)
	}
}
