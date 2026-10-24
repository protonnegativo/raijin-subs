// Package reduce turns raw subfinder and dnsx results into a small, ranked Raijin result.
//
// It is lossless for what an agent acts on: every subdomain subfinder found or dnsx resolved is kept,
// with its DNS status, CNAME chain, A and AAAA records. Names with the same answer collapse into one
// entry that lists every name. Only exact duplicates are dropped. A byte budget can cut, but every cut
// is counted in omitted.
package reduce

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/protonnegativo/raijin-subs/internal/dnsx"
	"github.com/protonnegativo/raijin-subs/internal/schema"
	"github.com/protonnegativo/raijin-subs/internal/subfinder"
)

// Options control what the reducer keeps.
type Options struct {
	MaxItems int // 0 keeps every finding
	MaxBytes int
	// Resolved is false when dnsx did not run: a name with no record is UNCHECKED instead of NOANSWER.
	Resolved bool
	// Sources writes the passive sources of each name in its location: "dev.example.com [crtsh]".
	Sources bool
	// WildcardMin is the number of names under one parent with the same answer before that parent is
	// probed for wildcard DNS (see WildcardParents).
	WildcardMin int
	InScope     func(name string) bool
}

// Defaults keep every finding. The byte cap is higher than the other Raijin tools': a subdomain list is
// long by nature, and 64,000 bytes holds about 2,000 names.
func Defaults() Options {
	return Options{MaxBytes: 64000, Resolved: true, WildcardMin: 5}
}

// The rules that make an answer a finding, in the order they are written. A finding takes the highest
// severity of its tags.
//
//	dangling     the name has a CNAME and the chain ends in NXDOMAIN: high when the target is a service
//	             where a name can be claimed (GitHub Pages, S3, Heroku, Azure...), medium otherwise
//	no-address   the name has a CNAME but no A or AAAA record: medium on a claimable service, low otherwise;
//	             not for names behind a wildcard, where a missing address is a flaky query, not a lead
//	private-ip   an A or AAAA record is private, loopback, link-local or CGNAT: medium
//	third-party  the CNAME chain points into a known third-party service that hosts content (not a CDN or
//	             load balancer in front of the owner's origin): low
//	name         a label says dev, staging, admin, vpn, jenkins and similar, and the name resolves: low
var tagOrder = []string{"dangling", "no-address", "private-ip", "third-party", "name"}

// interestingWords are labels (or parts of labels split on "-" and "_", trailing digits removed) that
// usually mean a non-production, internal or admin service.
var interestingWords = map[string]bool{}

var trailingDigits = regexp.MustCompile(`[0-9]+$`)

func init() {
	for _, w := range strings.Fields(`
		dev devel develop development stage staging stg test tests testing qa uat preprod pre-prod sandbox sbx
		demo beta alpha canary internal intranet corp private admin administrator adm panel console manage
		management mgmt portal vpn sslvpn remote rdp citrix owa exchange sso jenkins gitlab git jira confluence
		grafana kibana prometheus elastic elasticsearch ci build deploy debug backup backups bak old legacy db
		database sql mysql postgres redis mongo ftp sftp ssh vault k8s kube kubernetes docker registry nexus
		artifactory sonar sonarqube phpmyadmin wp-admin`) {
		interestingWords[w] = true
	}
}

type cluster struct {
	key         string
	ans         schema.Answer
	interesting bool
	words       map[string]bool
	locs        map[string]bool
}

type nameInfo struct {
	fromSubfinder bool
	sources       map[string]bool
	answers       []schema.Answer
	seen          map[string]bool // answer keys, for duplicates
}

// Reduce collapses the results into findings and groups: one entry per distinct answer, listing every
// name that has it. It also returns every location per finding fingerprint, before any budget, for --state.
func Reduce(hosts []subfinder.Result, records []dnsx.Record, opt Options) ([]schema.Finding, []schema.Group, map[string]int, map[string][]string) {
	omitted := map[string]int{}
	names := map[string]*nameInfo{}
	var order []string
	dropped := map[string]bool{}

	add := func(raw string) *nameInfo {
		n := Normalize(raw)
		if n == "" {
			return nil
		}
		if opt.InScope != nil && !opt.InScope(n) {
			if !dropped[n] {
				dropped[n] = true
				omitted["out_of_scope"]++
			}
			return nil
		}
		info, ok := names[n]
		if !ok {
			info = &nameInfo{sources: map[string]bool{}, seen: map[string]bool{}}
			names[n] = info
			order = append(order, n)
		}
		return info
	}

	for _, h := range hosts {
		info := add(h.Host)
		if info == nil {
			continue
		}
		if info.fromSubfinder {
			omitted["duplicates"]++
		}
		info.fromSubfinder = true
		for _, s := range h.Sources {
			info.sources[s] = true
		}
	}

	probes := map[string]schema.Answer{}
	for _, rec := range records {
		if rec.Probe() {
			if parent := Parent(Normalize(rec.Host)); parent != "" {
				probes[parent] = answer(rec)
			}
			continue
		}
		info := add(rec.Host)
		if info == nil {
			continue
		}
		a := answer(rec)
		k := answerKey(a)
		if info.seen[k] {
			omitted["duplicates"]++
			continue
		}
		info.seen[k] = true
		info.answers = append(info.answers, a)
	}

	clusters := map[string]*cluster{}
	var keys []string
	for _, n := range order {
		info := names[n]
		answers := info.answers
		if len(answers) == 0 {
			status := "NOANSWER"
			if !opt.Resolved {
				status = "UNCHECKED"
			}
			answers = []schema.Answer{{Status: status}}
		}
		for _, a := range answers {
			a.Wildcard = wildcard(n, a, probes)
			words := Words(n)
			interesting := len(words) > 0 && a.Wildcard == "" && hasAddress(a)
			key := answerKey(a)
			if interesting {
				key += "|name"
			}
			c, ok := clusters[key]
			if !ok {
				if p, ok := Provider(a.CNAME); ok {
					a.Provider = p.name
				}
				c = &cluster{key: key, ans: a, interesting: interesting, words: map[string]bool{}, locs: map[string]bool{}}
				clusters[key] = c
				keys = append(keys, key)
			}
			if interesting {
				for _, w := range words {
					c.words[w] = true
				}
			}
			c.locs[Location(n, info.sources, opt.Sources)] = true
		}
	}

	findings := []schema.Finding{}
	groups := []schema.Group{}
	allLocations := map[string][]string{}
	for _, key := range keys {
		c := clusters[key]
		locs := sorted(c.locs)
		tags := Tags(c.ans, c.interesting)
		if len(tags) == 0 {
			groups = append(groups, schema.Group{ID: groupPrefix(c.ans) + "-" + fingerprint(key)[:8], Answer: c.ans, Locations: locs, Count: len(locs)})
			continue
		}
		id := tags[0] + "-" + fingerprint(key)[:8]
		f := schema.Finding{ID: id, Title: Title(c.ans, tags, sorted(c.words)), Tags: tags, Answer: c.ans, Locations: locs, Count: len(locs), Fingerprint: fingerprint(id)}
		f.Severity = Severity(c.ans, tags)
		if heuristicOnly(tags) {
			f.Confidence = "heuristic"
		}
		allLocations[f.Fingerprint] = locs
		findings = append(findings, f)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if schema.SeverityRank[a.Severity] != schema.SeverityRank[b.Severity] {
			return schema.SeverityRank[a.Severity] > schema.SeverityRank[b.Severity]
		}
		if schema.ConfidenceRank[a.Confidence] != schema.ConfidenceRank[b.Confidence] {
			return schema.ConfidenceRank[a.Confidence] > schema.ConfidenceRank[b.Confidence]
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})
	// Names that resolve come before names that do not, so the budget cuts dead names first.
	sort.SliceStable(groups, func(i, j int) bool {
		a, b := groups[i], groups[j]
		if (a.Status == "") != (b.Status == "") {
			return a.Status == ""
		}
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		return a.ID < b.ID
	})

	if opt.MaxItems > 0 && len(findings) > opt.MaxItems {
		omitted["findings"] += len(findings) - opt.MaxItems
		findings = findings[:opt.MaxItems]
	}
	return findings, groups, omitted, allLocations
}

// Tags returns the rules an answer matches, in tagOrder. No tags means it goes to a group.
func Tags(a schema.Answer, interesting bool) []string {
	var tags []string
	p, known := Provider(a.CNAME)
	if len(a.CNAME) > 0 && a.Status == "NXDOMAIN" {
		tags = append(tags, "dangling")
	} else if len(a.CNAME) > 0 && !hasAddress(a) && a.Wildcard == "" {
		tags = append(tags, "no-address")
	}
	if privateAddress(a) {
		tags = append(tags, "private-ip")
	}
	if known && !p.edge {
		tags = append(tags, "third-party")
	}
	if interesting {
		tags = append(tags, "name")
	}
	return tags
}

// Severity is the highest severity of the tags (see tagOrder).
func Severity(a schema.Answer, tags []string) string {
	p, _ := Provider(a.CNAME)
	claimable := p.claimable
	best := ""
	for _, t := range tags {
		s := "low"
		switch t {
		case "dangling":
			s = "medium"
			if claimable {
				s = "high"
			}
		case "no-address":
			if claimable {
				s = "medium"
			}
		case "private-ip":
			s = "medium"
		}
		if best == "" || schema.SeverityRank[s] > schema.SeverityRank[best] {
			best = s
		}
	}
	return best
}

// heuristicOnly is true when every tag is a guess, not a DNS fact worth acting on by itself: a CNAME
// without an address is often a mail or DKIM record, and a name is only a name.
func heuristicOnly(tags []string) bool {
	for _, t := range tags {
		if t != "no-address" && t != "name" {
			return false
		}
	}
	return true
}

// Title is one line per finding, built from its tags.
func Title(a schema.Answer, tags []string, words []string) string {
	target := a.Provider
	if target == "" && len(a.CNAME) > 0 {
		target = a.CNAME[len(a.CNAME)-1]
	}
	var parts []string
	has := map[string]bool{}
	for _, t := range tags {
		has[t] = true
	}
	switch {
	case has["dangling"]:
		parts = append(parts, "Dangling CNAME to "+target)
	case has["no-address"]:
		parts = append(parts, "CNAME to "+target+" without an address")
	case has["third-party"]:
		parts = append(parts, "CNAME to "+target)
	}
	if has["private-ip"] {
		parts = append(parts, "Private IP in public DNS")
	}
	if has["name"] {
		parts = append(parts, "Interesting name: "+strings.Join(words, ", "))
	}
	return strings.Join(parts, "; ")
}

// WildcardParents returns the parents worth probing for wildcard DNS: those with at least min names
// whose answer (the same IPs, or the same CNAME chain) is identical. The parent of a root is never
// probed, so "example.com" is probed only for names below it.
func WildcardParents(records []dnsx.Record, roots []string, min int) []string {
	if min <= 0 {
		return nil
	}
	count := map[string]int{}
	for _, rec := range records {
		if rec.Probe() {
			continue
		}
		a := answer(rec)
		if a.Status != "" {
			continue
		}
		parent := Parent(Normalize(rec.Host))
		if parent == "" || !underRoot(parent, roots) {
			continue
		}
		count[parent+"\x00"+sameKey(a)]++
	}
	set := map[string]bool{}
	for k, n := range count {
		if n >= min {
			set[strings.SplitN(k, "\x00", 2)[0]] = true
		}
	}
	return sorted(set)
}

func underRoot(name string, roots []string) bool {
	if len(roots) == 0 {
		return strings.Contains(name, ".")
	}
	for _, r := range roots {
		r = Normalize(r)
		if name == r || strings.HasSuffix(name, "."+r) {
			return true
		}
	}
	return false
}

// wildcard returns "*.parent" for the closest parent whose random probe name got the same answer as
// the name, or "" if there is none.
func wildcard(name string, a schema.Answer, probes map[string]schema.Answer) string {
	if a.Status != "" || len(probes) == 0 {
		return ""
	}
	for p := Parent(name); p != ""; p = Parent(p) {
		if pa, ok := probes[p]; ok && pa.Status == "" && sameKey(pa) == sameKey(a) {
			return "*." + p
		}
	}
	return ""
}

// sameKey is what makes a wildcard answer match: the CNAME chain when there is one (a CDN answers with
// other IPs on each query), the A and AAAA records otherwise.
func sameKey(a schema.Answer) string {
	if len(a.CNAME) > 0 {
		return "cname:" + strings.Join(a.CNAME, ",")
	}
	return "ip:" + strings.Join(a.A, ",") + "|" + strings.Join(a.AAAA, ",")
}

func answer(rec dnsx.Record) schema.Answer {
	a := schema.Answer{
		Status: strings.ToUpper(strings.TrimSpace(rec.StatusCode)),
		A:      uniqueSorted(rec.A),
		AAAA:   uniqueSorted(rec.AAAA),
	}
	for _, c := range rec.CNAME {
		c = Normalize(c)
		if c != "" && (len(a.CNAME) == 0 || a.CNAME[len(a.CNAME)-1] != c) {
			a.CNAME = append(a.CNAME, c)
		}
	}
	if a.Status == "NOERROR" {
		a.Status = ""
		if len(a.A)+len(a.AAAA)+len(a.CNAME) == 0 {
			a.Status = "NODATA"
		}
	}
	return a
}

// answerKey is what makes two names the same: status, CNAME chain, A, AAAA and wildcard.
func answerKey(a schema.Answer) string {
	b, _ := schema.Marshal([]any{a.Status, a.CNAME, a.A, a.AAAA, a.Wildcard})
	return string(b)
}

func groupPrefix(a schema.Answer) string {
	switch {
	case a.Status != "":
		return strings.ToLower(a.Status)
	case a.Wildcard != "":
		return "wildcard"
	case len(a.CNAME) > 0:
		return "cname"
	}
	return "a"
}

func hasAddress(a schema.Answer) bool {
	return len(a.A)+len(a.AAAA) > 0
}

var cgnat = &net.IPNet{IP: net.IP{100, 64, 0, 0}, Mask: net.CIDRMask(10, 32)}

// privateAddress is true when an A or AAAA record is not a public address: RFC 1918, RFC 4193,
// loopback, link-local, unspecified or CGNAT (100.64.0.0/10).
func privateAddress(a schema.Answer) bool {
	for _, s := range append(append([]string(nil), a.A...), a.AAAA...) {
		ip := net.ParseIP(s)
		if ip == nil {
			continue
		}
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || cgnat.Contains(ip) {
			return true
		}
	}
	return false
}

// Words returns the interesting words in the labels of a name, below its last two labels, sorted. The
// registered domain is never a hint, and neither is its name inside a label: "gitlab" is not
// interesting under gitlab.com.
func Words(name string) []string {
	labels := strings.Split(name, ".")
	if len(labels) <= 2 {
		return nil
	}
	brand := labels[len(labels)-2]
	set := map[string]bool{}
	for _, l := range labels[:len(labels)-2] {
		parts := []string{l}
		if !interestingWords[l] {
			parts = strings.FieldsFunc(l, func(r rune) bool { return r == '-' || r == '_' })
		}
		for _, part := range parts {
			if !interestingWords[part] {
				part = trailingDigits.ReplaceAllString(part, "")
			}
			if interestingWords[part] && part != brand {
				set[part] = true
			}
		}
	}
	return sorted(set)
}

// Location is one name: "name" or, with --sources, "name [source, ...]".
func Location(name string, sources map[string]bool, withSources bool) string {
	if !withSources || len(sources) == 0 {
		return name
	}
	return name + " [" + strings.Join(sorted(sources), ", ") + "]"
}

// Normalize lowercases a name and removes the trailing dot and a leading "*.".
func Normalize(s string) string {
	s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	return strings.TrimPrefix(s, "*.")
}

// Parent is the name without its first label, or "" when that would leave a single label.
func Parent(name string) string {
	i := strings.IndexByte(name, '.')
	if i < 0 || !strings.Contains(name[i+1:], ".") {
		return ""
	}
	return name[i+1:]
}

// Fit shrinks the result until its JSON is at most maxBytes. It cuts the least important data first:
// group locations, then groups, then the locations of the lowest-ranked findings (each keeps one, and
// its count), then the lowest-ranked findings. Every cut is counted in Omitted.
func Fit(res *schema.Result, maxBytes int) {
	if maxBytes <= 0 || size(res) <= maxBytes {
		return
	}
	res.Budget.Truncated = true
	if res.Omitted == nil {
		res.Omitted = map[string]int{}
	}
	total := size(res) // now includes the budget object
	for i := len(res.Groups) - 1; i >= 0 && total > maxBytes; i-- {
		g := &res.Groups[i]
		before := size(g)
		res.Omitted["locations"] += len(g.Locations)
		g.Locations = nil
		total += size(g) - before
	}
	for total > maxBytes && len(res.Groups) > 0 {
		last := len(res.Groups) - 1
		total -= size(res.Groups[last]) + 1
		res.Groups = res.Groups[:last]
		res.Omitted["groups"]++
	}
	for i := len(res.Findings) - 1; i >= 0 && total > maxBytes; i-- {
		f := &res.Findings[i]
		if len(f.Locations) <= 1 {
			continue
		}
		before := size(f)
		res.Omitted["locations"] += len(f.Locations) - 1
		f.Locations = f.Locations[:1]
		total += size(f) - before
	}
	for total > maxBytes && len(res.Findings) > 1 {
		last := len(res.Findings) - 1
		total -= size(res.Findings[last]) + 1
		res.Findings = res.Findings[:last]
		res.Omitted["findings"]++
	}
	// the estimate above ignores the omitted counters it adds; settle on the real size
	for size(res) > maxBytes && len(res.Findings) > 1 {
		res.Findings = res.Findings[:len(res.Findings)-1]
		res.Omitted["findings"]++
	}
}

func size(v any) int {
	b, _ := schema.Marshal(v)
	return len(b)
}

func uniqueSorted(in []string) []string {
	set := map[string]bool{}
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			set[s] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return sorted(set)
}

func sorted(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func fingerprint(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:8])
}
