// Command raijin-subs runs subfinder and dnsx and returns a small, grouped, ranked result for AI agents.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-subs/internal/banner"
	"github.com/protonnegativo/raijin-subs/internal/dnsx"
	"github.com/protonnegativo/raijin-subs/internal/engines"
	"github.com/protonnegativo/raijin-subs/internal/reduce"
	"github.com/protonnegativo/raijin-subs/internal/schema"
	"github.com/protonnegativo/raijin-subs/internal/scope"
	"github.com/protonnegativo/raijin-subs/internal/state"
	"github.com/protonnegativo/raijin-subs/internal/subfinder"
)

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(v string) error { *m = append(*m, v); return nil }

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-subs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var domains, inputs multi
	fs.Var(&domains, "d", "root domain to enumerate (repeatable; default: every host the scope names)")
	list := fs.String("l", "", "file with one root domain per line")
	scopeFile := fs.String("scope", "", "scope file (required): domains, *.wildcards, IPs, CIDRs, !exclusions")
	noResolve := fs.Bool("no-resolve", false, "only enumerate; do not resolve the names with dnsx")
	sources := fs.Bool("sources", false, "write the passive sources of each name in its location")
	rate := fs.Int("rate", 0, "DNS queries per second (dnsx -rl)")
	threads := fs.Int("threads", 0, "concurrent DNS queries (dnsx -t)")
	resolvers := fs.String("resolvers", "", "DNS resolvers, a file or comma-separated list (dnsx -r)")
	timeout := fs.Int("timeout", 0, "seconds to wait for each passive source (subfinder -timeout)")
	maxTime := fs.Int("max-time", 0, "minutes to wait for the whole enumeration (subfinder -max-time)")
	maxItems := fs.Int("max-items", 0, "maximum findings in the output (0 keeps all)")
	maxBytes := fs.Int("max-bytes", reduce.Defaults().MaxBytes, "maximum size of the JSON output; cuts are counted in omitted")
	rawPath := fs.String("raw", "", "file for subfinder's and dnsx's full JSONL output (default: a new file in the temp dir)")
	statePath := fs.String("state", "", "state file; marks findings that are new since the last run")
	format := fs.String("format", "json", "output format: json or table")
	pretty := fs.Bool("pretty", false, "indent the JSON (compact by default, which costs fewer tokens)")
	fs.Var(&inputs, "input", "read existing subfinder and/or dnsx JSONL instead of running them (repeatable)")
	sfBin := fs.String("subfinder", "subfinder", "path to the subfinder binary")
	dnsxBin := fs.String("dnsx", "dnsx", "path to the dnsx binary")
	showVersion := fs.Bool("version", false, "print the version")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-subs --scope scope.txt [-d domain | -l domains.txt | --input results.jsonl] [flags] [-- extra subfinder args]\n\nWith no targets it enumerates every host the scope names.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-subs", version, useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, versionLine())
		return 0
	}
	if *scopeFile == "" {
		fmt.Fprintln(stderr, "raijin-subs: --scope is required")
		return 1
	}
	sc, err := scope.Load(*scopeFile)
	if err != nil {
		fmt.Fprintln(stderr, "raijin-subs: scope:", err)
		return 1
	}

	res := schema.Result{
		Tool:     "raijin-subs",
		Version:  version,
		Findings: []schema.Finding{},
		Groups:   []schema.Group{},
		Omitted:  map[string]int{},
		Errors:   []schema.Error{},
		Next:     []string{},
		Budget:   schema.Budget{MaxItems: *maxItems, MaxBytes: *maxBytes},
	}
	opt := reduce.Defaults()
	opt.MaxItems = *maxItems
	opt.MaxBytes = *maxBytes
	opt.Sources = *sources
	opt.InScope = sc.Allowed

	var hosts []subfinder.Result
	var records []dnsx.Record
	code := 0
	if len(inputs) > 0 {
		for _, in := range inputs {
			b, err := os.ReadFile(in)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-subs:", err)
				return 1
			}
			h, err1 := subfinder.Parse(bytes.NewReader(b))
			r, err2 := dnsx.Parse(bytes.NewReader(b))
			if err := errors.Join(err1, err2); err != nil {
				fmt.Fprintln(stderr, "raijin-subs:", err)
				return 1
			}
			hosts = append(hosts, h...)
			records = append(records, r...)
		}
		// A replay never runs an engine: names without a dnsx record were not resolved, unless the
		// input has dnsx records, in which case dnsx ran and returned nothing for them.
		opt.Resolved = len(records) > 0
		res.Target = strings.Join(inputs, ", ")
	} else {
		if *list != "" {
			lines, err := readLines(*list)
			if err != nil {
				fmt.Fprintln(stderr, "raijin-subs:", err)
				return 1
			}
			domains = append(domains, lines...)
		}
		if len(domains) == 0 {
			// no targets given: enumerate the domains the scope names, and the apex of each wildcard.
			// IPs and ranges are not root domains.
			targets, wildcards, _ := sc.Targets()
			for _, t := range targets {
				if net.ParseIP(t) == nil {
					domains = append(domains, t)
				}
			}
			for _, w := range wildcards {
				domains = append(domains, strings.TrimPrefix(w, "*."))
			}
		}
		roots := filter(domains, sc, res.Omitted)
		if len(roots) == 0 {
			fmt.Fprintln(stderr, "raijin-subs: no root domains in scope")
			return 1
		}
		res.Target = targetSummary(roots, res.Omitted["out_of_scope"])

		if *rawPath == "" {
			f, err := os.CreateTemp("", "raijin-subs-*.jsonl")
			if err != nil {
				fmt.Fprintln(stderr, "raijin-subs:", err)
				return 1
			}
			f.Close()
			*rawPath = f.Name()
		}
		raw, err := os.Create(*rawPath)
		if err != nil {
			fmt.Fprintln(stderr, "raijin-subs:", err)
			return 1
		}
		defer raw.Close()
		res.Raw = *rawPath

		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		var stderrTail string
		checkVersion(ctx, "subfinder", *sfBin, &res)
		var sfStats subfinder.Stats
		hosts, stderrTail, err = subfinder.Run(ctx, roots, subfinder.Options{
			Binary: *sfBin, Timeout: *timeout, MaxTime: *maxTime, Extra: fs.Args(), Raw: raw, Stats: &sfStats,
		})
		switch {
		case errors.Is(err, subfinder.ErrNotFound):
			res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install subfinder (go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest) or pass --subfinder <path>, or run raijin-mcp update"})
			res.Summary = "subfinder not found, nothing enumerated"
			res.Raw = ""
			raw.Close()
			os.Remove(*rawPath)
			write(stdout, &res, *format, *pretty)
			return 2
		case err != nil:
			res.Errors = append(res.Errors, engineError(err, stderrTail))
		}
		// Output lines without the fields the reducer reads: the engine's format may have changed.
		if sfStats.Bad > 0 {
			res.Errors = append(res.Errors, engines.Format("subfinder", sfStats.Bad, sfStats.Lines, subfinder.Fields, *rawPath))
			res.Omitted["unparsed"] += sfStats.Unparsed
		}

		opt.Resolved = !*noResolve
		var dxStats dnsx.Stats
		if names := namesInScope(hosts, sc); !*noResolve && len(names) > 0 {
			checkVersion(ctx, "dnsx", *dnsxBin, &res)
			dopt := dnsx.Options{Binary: *dnsxBin, Rate: *rate, Threads: *threads, Resolvers: *resolvers, Raw: raw, Stats: &dxStats}
			records, stderrTail, err = dnsx.Run(ctx, names, dopt)
			switch {
			case errors.Is(err, dnsx.ErrNotFound):
				res.Errors = append(res.Errors, schema.Error{Kind: "missing_engine", Hint: "install dnsx (go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest) or pass --dnsx <path>, or run raijin-mcp update; the names below are not resolved"})
				opt.Resolved = false
				code = 2
			case err != nil:
				res.Errors = append(res.Errors, engineError(err, stderrTail))
			}
			// Wildcard check: one random name under each parent where many names share an answer.
			// It is one DNS query per parent, sent to the resolvers like every other query.
			var probes []string
			for _, p := range reduce.WildcardParents(records, roots, opt.WildcardMin) {
				if name := dnsx.ProbeName(p); sc.Allowed(name) {
					probes = append(probes, name)
				}
			}
			if code == 0 && len(probes) > 0 {
				more, stderrTail, err := dnsx.Run(ctx, probes, dopt)
				if err != nil {
					res.Errors = append(res.Errors, engineError(err, stderrTail))
				}
				records = append(records, more...)
			}
		}
		if dxStats.Bad > 0 {
			res.Errors = append(res.Errors, engines.Format("dnsx", dxStats.Bad, dxStats.Lines, dnsx.Fields, *rawPath))
			res.Omitted["unparsed"] += dxStats.Bad
		}
	}

	findings, groups, omitted, allLocations := reduce.Reduce(hosts, records, opt)
	res.Findings, res.Groups = findings, groups
	for k, v := range omitted {
		res.Omitted[k] += v
	}

	newCount := -1
	if *statePath != "" {
		st, err := state.Load(*statePath)
		if err != nil {
			res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
		} else {
			newCount = st.Mark(res.Findings, allLocations)
			if err := st.Save(*statePath); err != nil {
				res.Errors = append(res.Errors, schema.Error{Kind: "state_error", Hint: err.Error()})
			}
		}
	}

	res.Summary = summary(res, opt.Resolved, newCount)
	if res.Omitted["findings"] > 0 {
		res.Budget.Truncated = true
	}
	reduce.Fit(&res, *maxBytes)
	if res.Budget.Truncated {
		hint := "raise --max-bytes"
		if src := res.Raw + strings.Join(inputs, ", "); src != "" {
			hint += " or read " + src + " for what was cut"
		}
		res.Next = append(res.Next, hint)
		reduce.Fit(&res, *maxBytes) // the hint takes room too
	}
	write(stdout, &res, *format, *pretty)
	return code
}

// checkVersion adds an engine_version error when the installed engine is not a tested version. A missing
// binary is left to the run, which reports it.
func checkVersion(ctx context.Context, name, bin string, res *schema.Result) {
	path, err := exec.LookPath(bin)
	if err != nil {
		return
	}
	if e, ok := engines.Check(ctx, name, path); ok {
		res.Errors = append(res.Errors, e)
	}
}

func engineError(err error, stderrTail string) schema.Error {
	hint := err.Error()
	if stderrTail != "" {
		hint += ": " + stderrTail
	}
	return schema.Error{Kind: "engine_error", Hint: hint}
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// filter keeps the root domains the scope covers: the root itself, or its subdomains (*.example.com).
func filter(domains []string, sc *scope.Scope, omitted map[string]int) []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range domains {
		d = reduce.Normalize(d)
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		if !sc.Covers(d) {
			omitted["out_of_scope"]++
			continue
		}
		out = append(out, d)
	}
	return out
}

// namesInScope is what dnsx resolves: every name subfinder found that is in scope, once.
func namesInScope(hosts []subfinder.Result, sc *scope.Scope) []string {
	seen := map[string]bool{}
	var out []string
	for _, h := range hosts {
		n := reduce.Normalize(h.Host)
		if n == "" || seen[n] || !sc.Allowed(n) {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out
}

func targetSummary(roots []string, skipped int) string {
	s := fmt.Sprintf("%d domain(s)", len(roots))
	if len(roots) == 1 {
		s = roots[0]
	}
	if skipped > 0 {
		s += fmt.Sprintf(" (%d out of scope skipped)", skipped)
	}
	return s
}

// summary is written before the budget, so it stays true when Fit cuts.
func summary(res schema.Result, resolved bool, newCount int) string {
	names, live := map[string]bool{}, map[string]bool{}
	wildcards := map[string]bool{}
	count := func(a schema.Answer, locs []string) {
		for _, l := range locs {
			n := strings.SplitN(l, " ", 2)[0]
			names[n] = true
			if a.Status == "" {
				live[n] = true
			}
		}
		if a.Wildcard != "" {
			wildcards[a.Wildcard] = true
		}
	}
	bySev := map[string]int{}
	for _, f := range res.Findings {
		bySev[f.Severity]++
		count(f.Answer, f.Locations)
	}
	for _, g := range res.Groups {
		count(g.Answer, g.Locations)
	}
	var parts []string
	for _, sev := range []string{"critical", "high", "medium", "low", "info", "unknown"} {
		if n := bySev[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	s := fmt.Sprintf("%d names", len(names))
	if resolved {
		s += fmt.Sprintf(", %d resolve", len(live))
	} else {
		s += " (not resolved)"
	}
	s += fmt.Sprintf(", %d findings", len(res.Findings))
	if len(parts) > 0 {
		s += " (" + strings.Join(parts, ", ") + ")"
	}
	s += fmt.Sprintf(", %d groups", len(res.Groups))
	if len(wildcards) > 0 {
		var w []string
		for k := range wildcards {
			w = append(w, k)
		}
		sort.Strings(w)
		s += ", wildcard " + strings.Join(w, " ")
	}
	if newCount >= 0 {
		s += fmt.Sprintf(", %d new", newCount)
	}
	return s
}

func write(w io.Writer, res *schema.Result, format string, pretty bool) {
	if format == "table" {
		fmt.Fprintln(w, res.Summary)
		for _, f := range res.Findings {
			mark := ""
			if f.New {
				mark = " [new]"
			}
			fmt.Fprintf(w, "%-8s %s %s (%d)%s\n", strings.ToUpper(f.Severity), strings.Join(f.Tags, ","), f.Title, max(f.Count, len(f.Locations)), mark)
			for _, l := range f.Locations {
				fmt.Fprintf(w, "         %s\n", l)
			}
		}
		for _, g := range res.Groups {
			fmt.Fprintf(w, "group    %s (%d)\n", describe(g.Answer), max(g.Count, len(g.Locations)))
		}
		for _, e := range res.Errors {
			fmt.Fprintf(w, "error    %s: %s\n", e.Kind, e.Hint)
		}
		return
	}
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if pretty {
		enc.SetIndent("", "  ")
	}
	_ = enc.Encode(res)
}

// describe is a one-line view of an answer for the table: the status, or the CNAME target and IPs.
func describe(a schema.Answer) string {
	if a.Status != "" {
		s := a.Status
		if len(a.CNAME) > 0 {
			s += " -> " + a.CNAME[len(a.CNAME)-1]
		}
		return s
	}
	var parts []string
	if len(a.CNAME) > 0 {
		parts = append(parts, "-> "+a.CNAME[len(a.CNAME)-1])
	}
	ips := append(append([]string(nil), a.A...), a.AAAA...)
	if len(ips) > 2 {
		ips = append(ips[:2], fmt.Sprintf("+%d", len(ips)-2))
	}
	parts = append(parts, strings.Join(ips, " "))
	if a.Wildcard != "" {
		parts = append(parts, "wildcard "+a.Wildcard)
	}
	return strings.Join(parts, " ")
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if l := strings.TrimSpace(sc.Text()); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out, sc.Err()
}
