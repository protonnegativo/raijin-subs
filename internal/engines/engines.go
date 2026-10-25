// Package engines knows the engine versions raijin-subs was tested with (engines.json) and warns, in
// errors, when the installed engine is a different version or its output looks different.
package engines

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	raijinsubs "github.com/protonnegativo/raijin-subs"
	"github.com/protonnegativo/raijin-subs/internal/schema"
)

// Engine is one entry of engines.json: the tested version and the install source (one of Go, Pip,
// System).
type Engine struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`
	Pip     string `json:"pip,omitempty"`
	System  string `json:"system,omitempty"`
}

// Install is the command that installs version v of the engine.
func (e Engine) Install(v string) string {
	switch {
	case e.Go != "":
		return "go install " + e.Go + "@v" + v
	case e.Pip != "":
		return "pip install " + e.Pip + "==" + v
	default:
		return "install " + e.System + " " + v + " from your system's packages"
	}
}

// Tested parses the embedded engines.json.
func Tested() (map[string]Engine, error) {
	var m map[string]Engine
	if err := json.Unmarshal(raijinsubs.EnginesJSON, &m); err != nil {
		return nil, fmt.Errorf("engines.json: %w", err)
	}
	return m, nil
}

// VersionArgs is the command line that prints each engine's version. -duc skips the update check, which
// would ask the network.
var VersionArgs = map[string][]string{
	"subfinder": {"-version", "-duc"},
	"dnsx":      {"-version", "-duc"},
}

var versionRe = regexp.MustCompile(`v?(\d+)\.(\d+)\.(\d+)`)

// ParseVersion returns the first X.Y.Z in the output of a version command ("Current Version: v2.6.7"),
// without the v, or "" when there is none.
func ParseVersion(out string) string {
	m := versionRe.FindStringSubmatch(out)
	if m == nil {
		return ""
	}
	return m[1] + "." + m[2] + "." + m[3]
}

func parts(v string) []int {
	var p []int
	for _, s := range strings.Split(v, ".") {
		n, err := strconv.Atoi(s)
		if err != nil {
			return nil
		}
		p = append(p, n)
	}
	if len(p) != 3 {
		return nil
	}
	return p
}

// Untested reports whether the installed version should be warned about: another major version, or
// older than the tested one. A newer minor or patch of the same major is fine (the weekly drift job
// tests it), and so is a version that does not parse.
func Untested(installed, tested string) bool {
	a, b := parts(installed), parts(tested)
	if a == nil || b == nil {
		return false
	}
	if a[0] != b[0] {
		return true
	}
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

// InRange reports whether version v is in r, comma-separated constraints that all hold (">=1.3.0",
// ">=1.3.0,<1.3.5"). A version or a constraint that does not parse is never in range.
func InRange(v, r string) bool {
	a := parts(v)
	if a == nil || r == "" {
		return false
	}
	for _, c := range strings.Split(r, ",") {
		c = strings.TrimSpace(c)
		op := strings.TrimRight(c, "0123456789.v")
		b := parts(strings.TrimPrefix(c[len(op):], "v"))
		if b == nil {
			return false
		}
		cmp := 0
		for i := 0; i < 3 && cmp == 0; i++ {
			if a[i] != b[i] {
				cmp = 1
				if a[i] < b[i] {
					cmp = -1
				}
			}
		}
		ok := false
		switch op {
		case ">=":
			ok = cmp >= 0
		case ">":
			ok = cmp > 0
		case "<=":
			ok = cmp <= 0
		case "<":
			ok = cmp < 0
		}
		if !ok {
			return false
		}
	}
	return true
}

// KnownBad returns the regression of the installed version of the engine, if raijinsubs.KnownBad lists it.
func KnownBad(name, installed string) (raijinsubs.Bad, bool) {
	b, ok := raijinsubs.KnownBad[name]
	return b, ok && InRange(installed, b.Range)
}

// Check runs the engine's version command (3s at most) and returns an engine_version error when the
// installed version is untested. It never fails: anything it cannot tell is silent.
func Check(ctx context.Context, name, path string) (schema.Error, bool) {
	tested, err := Tested()
	if err != nil {
		return schema.Error{}, false
	}
	e, ok := tested[name]
	if !ok {
		return schema.Error{}, false
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, VersionArgs[name]...)
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run()
	installed := ParseVersion(out.String())
	if b, bad := KnownBad(name, installed); bad {
		return schema.Error{Kind: "engine_version", Hint: fmt.Sprintf("%s %s is a known-bad version (%s): %s; results are incomplete. Install the tested version: %s, or run raijin-mcp update --pinned",
			name, installed, b.Range, b.Why, e.Install(e.Version))}, true
	}
	if installed == "" || !Untested(installed, e.Version) {
		return schema.Error{}, false
	}
	return schema.Error{Kind: "engine_version", Hint: fmt.Sprintf("%s %s is not the tested %s; results may be incomplete. Install the tested version: %s, or run raijin-mcp update",
		name, installed, e.Version, e.Install(e.Version))}, true
}

// Format is the engine_format error for bad of total output lines that had no fields.
func Format(name string, bad, total int, fields, raw string) schema.Error {
	return schema.Error{Kind: "engine_format", Hint: fmt.Sprintf("%d of %d %s results had no %s; the engine's output format may have changed. Read %s for the full output",
		bad, total, name, fields, raw)}
}

// NoLine is the engine_format error when dnsx wrote no line for missing of total names it was given.
func NoLine(missing, total int) schema.Error {
	hint := fmt.Sprintf("dnsx wrote no line for %d of %d names; dnsx 1.3.0+ drops names without records from -json even with -rcode (projectdiscovery/dnsx#1091).", missing, total)
	if m, err := Tested(); err == nil && m["dnsx"].Version != "" {
		e := m["dnsx"]
		hint += fmt.Sprintf(" Install dnsx %s: %s, or run raijin-mcp update --pinned", e.Version, e.Install(e.Version))
	}
	return schema.Error{Kind: "engine_format", Hint: hint}
}
