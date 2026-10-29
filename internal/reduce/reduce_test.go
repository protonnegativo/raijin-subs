package reduce

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/protonnegativo/raijin-subs/internal/dnsx"
	"github.com/protonnegativo/raijin-subs/internal/schema"
	"github.com/protonnegativo/raijin-core/scope"
	"github.com/protonnegativo/raijin-subs/internal/subfinder"
)

func load(t *testing.T) ([]subfinder.Result, []dnsx.Record) {
	t.Helper()
	b, err := os.ReadFile("../../testdata/sample.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	hosts, err := subfinder.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	records, err := dnsx.Parse(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return hosts, records
}

func inScope(t *testing.T) Options {
	t.Helper()
	sc, _ := scope.Parse([]string{"*.example.com"})
	opt := Defaults()
	opt.InScope = sc.Allowed
	return opt
}

// entries maps every name to the entries (finding or group IDs) it is listed in.
func entries(findings []schema.Finding, groups []schema.Group) map[string][]string {
	out := map[string][]string{}
	for _, f := range findings {
		for _, l := range f.Locations {
			out[l] = append(out[l], f.ID)
		}
	}
	for _, g := range groups {
		for _, l := range g.Locations {
			out[l] = append(out[l], g.ID)
		}
	}
	return out
}

func rec(host, status string, a []string, cname ...string) dnsx.Record {
	return dnsx.Record{Host: host, StatusCode: status, A: a, CNAME: cname}
}

func TestReduce(t *testing.T) {
	hosts, records := load(t)
	if len(hosts) != 18 || len(records) != 18 {
		t.Fatalf("parsed %d hosts and %d records, want 18 and 18 (the log line is skipped)", len(hosts), len(records))
	}
	findings, groups, omitted, all := Reduce(hosts, records, inScope(t))

	var got []string
	for _, f := range findings {
		got = append(got, f.Severity+":"+strings.Join(f.Tags, ",")+":"+strings.Join(f.Locations, ","))
	}
	want := []string{
		"high:dangling,third-party:docs.example.com",
		"medium:no-address,third-party:status.example.com",
		"medium:private-ip,name:intranet.example.com",
		"low:third-party:mail.example.com",
		"low:name:dev.example.com",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if f := findings[0]; f.Title != "Dangling CNAME to GitHub Pages" || f.Status != "NXDOMAIN" || f.Provider != "GitHub Pages" || f.CNAME[0] != "acme-docs.github.io" {
		t.Errorf("dangling finding = %+v", f)
	}
	if f := findings[4]; f.Confidence != "heuristic" || f.Title != "Interesting name: dev" {
		t.Errorf("a name alone is a heuristic: %+v", f)
	}

	var gotGroups []string
	for _, g := range groups {
		gotGroups = append(gotGroups, strings.SplitN(g.ID, "-", 2)[0]+":"+strings.Join(g.Locations, ","))
	}
	wantGroups := []string{
		"wildcard:a.wild.example.com,admin.wild.example.com,b.wild.example.com,c.wild.example.com,d.wild.example.com",
		"a:api.example.com,www.example.com",
		"cname:cdn.example.com",
		"noanswer:missing.example.com",
		"nodata:gone.example.com",
		"nxdomain:old.example.com",
	}
	if strings.Join(gotGroups, "\n") != strings.Join(wantGroups, "\n") {
		t.Errorf("groups:\n%s\nwant:\n%s", strings.Join(gotGroups, "\n"), strings.Join(wantGroups, "\n"))
	}
	if g := groups[0]; g.Wildcard != "*.wild.example.com" {
		t.Errorf("wildcard group = %+v", g)
	}
	if g := groups[2]; g.Provider != "Amazon CloudFront" {
		t.Errorf("a CNAME to a CDN keeps its provider but is a group: %+v", g)
	}
	if omitted["duplicates"] != 2 || omitted["out_of_scope"] != 1 {
		t.Errorf("omitted = %v", omitted)
	}
	if len(all[findings[0].Fingerprint]) != 1 {
		t.Errorf("state locations for the dangling finding = %v", all[findings[0].Fingerprint])
	}
}

// Lossless: every name subfinder found or dnsx resolved is in exactly one entry per answer it has.
func TestEveryNameIsListed(t *testing.T) {
	hosts, records := load(t)
	findings, groups, _, _ := Reduce(hosts, records, inScope(t))
	listed := entries(findings, groups)
	for _, h := range hosts {
		if h.Host == "outside.example.org" {
			continue
		}
		if len(listed[h.Host]) != 1 {
			t.Errorf("%s is listed in %v, want exactly one entry", h.Host, listed[h.Host])
		}
	}
	if len(listed) != 16 {
		t.Errorf("%d names listed, want 16", len(listed))
	}
}

// Lossless: a name dnsx resolved but subfinder did not return (a dnsx-only input) is still listed.
func TestDnsxOnlyNameIsListed(t *testing.T) {
	findings, groups, _, _ := Reduce(nil, []dnsx.Record{rec("only.example.com", "NOERROR", []string{"192.0.2.1"})}, inScope(t))
	if len(entries(findings, groups)["only.example.com"]) != 1 {
		t.Errorf("dnsx-only name missing: %+v %+v", findings, groups)
	}
}

// Lossless: without dnsx, every name is listed as UNCHECKED; with dnsx and no record, as NOANSWER.
func TestUnresolvedNamesAreListed(t *testing.T) {
	hosts := []subfinder.Result{{Host: "a.example.com"}, {Host: "b.example.com"}}
	opt := inScope(t)
	opt.Resolved = false
	_, groups, _, _ := Reduce(hosts, nil, opt)
	if len(groups) != 1 || groups[0].Status != "UNCHECKED" || len(groups[0].Locations) != 2 {
		t.Errorf("not resolved: %+v", groups)
	}
	opt.Resolved = true
	_, groups, _, _ = Reduce(hosts, []dnsx.Record{rec("a.example.com", "NXDOMAIN", nil)}, opt)
	if len(groups) != 2 || groups[0].Status != "NOANSWER" || groups[1].Status != "NXDOMAIN" {
		t.Errorf("resolved with one missing record: %+v", groups)
	}
}

// Lossless: the same name with two different answers (two replayed runs) is kept in both entries.
func TestSameNameDifferentAnswerIsKept(t *testing.T) {
	records := []dnsx.Record{
		rec("a.example.com", "NOERROR", []string{"192.0.2.1"}),
		rec("a.example.com", "NOERROR", []string{"192.0.2.2"}),
	}
	findings, groups, omitted, _ := Reduce(nil, records, inScope(t))
	if len(entries(findings, groups)["a.example.com"]) != 2 || omitted["duplicates"] != 0 {
		t.Errorf("both answers must be kept: %+v %v", groups, omitted)
	}
}

// Only exact repeats collapse: the same answer in another record order is a duplicate.
func TestExactDuplicatesAreCounted(t *testing.T) {
	records := []dnsx.Record{
		rec("a.example.com", "NOERROR", []string{"192.0.2.2", "192.0.2.1"}),
		rec("a.example.com", "noerror", []string{"192.0.2.1", "192.0.2.2", "192.0.2.1"}),
	}
	hosts := []subfinder.Result{{Host: "A.example.com.", Sources: []string{"crtsh"}}, {Host: "a.example.com", Sources: []string{"anubis"}}}
	opt := inScope(t)
	opt.Sources = true
	_, groups, omitted, _ := Reduce(hosts, records, opt)
	if len(groups) != 1 || len(groups[0].Locations) != 1 || omitted["duplicates"] != 2 {
		t.Fatalf("groups=%+v omitted=%v", groups, omitted)
	}
	if groups[0].Locations[0] != "a.example.com [anubis, crtsh]" {
		t.Errorf("the sources of a repeated name are merged: %q", groups[0].Locations[0])
	}
}

// Lossless: names that share IPs collapse into one group, but every name is in it.
func TestSameIPsCollapseIntoOneGroup(t *testing.T) {
	var records []dnsx.Record
	for i := 0; i < 30; i++ {
		records = append(records, rec(fmt.Sprintf("h%02d.example.com", i), "NOERROR", []string{"192.0.2.2", "192.0.2.1"}))
	}
	_, groups, _, _ := Reduce(nil, records, inScope(t))
	if len(groups) != 1 || len(groups[0].Locations) != 30 || strings.Join(groups[0].A, ",") != "192.0.2.1,192.0.2.2" {
		t.Errorf("groups = %+v", groups)
	}
}

// Lossless: an interesting name is split out of its group, and the rest of the group stays complete.
func TestInterestingNameIsSplitOut(t *testing.T) {
	records := []dnsx.Record{
		rec("www.example.com", "NOERROR", []string{"192.0.2.1"}),
		rec("jenkins.example.com", "NOERROR", []string{"192.0.2.1"}),
		rec("vpn-2.example.com", "NOERROR", []string{"192.0.2.1"}),
		rec("staging.example.com", "NXDOMAIN", nil),
	}
	findings, groups, _, _ := Reduce(nil, records, inScope(t))
	if len(findings) != 1 || strings.Join(findings[0].Locations, ",") != "jenkins.example.com,vpn-2.example.com" || findings[0].Title != "Interesting name: jenkins, vpn" {
		t.Errorf("findings = %+v", findings)
	}
	if len(groups) != 2 || strings.Join(groups[0].Locations, ",") != "www.example.com" || groups[1].Locations[0] != "staging.example.com" {
		t.Errorf("a name that does not resolve is not a finding, and the group keeps the rest: %+v", groups)
	}
}

// Lossless: names behind a wildcard are all listed; the wildcard only labels them and turns off the
// name rule. A name under the wildcard parent with another answer is real and is not labelled.
func TestWildcardLabelsButKeepsEveryName(t *testing.T) {
	records := []dnsx.Record{
		rec("dev.w.example.com", "NOERROR", []string{"192.0.2.9"}),
		rec("x.w.example.com", "NOERROR", []string{"192.0.2.9"}),
		rec("deep.x.w.example.com", "NOERROR", []string{"192.0.2.9"}),
		rec("real.w.example.com", "NOERROR", []string{"192.0.2.10"}),
		rec(dnsx.ProbePrefix+"00ff00ff.w.example.com", "NOERROR", []string{"192.0.2.9"}),
	}
	findings, groups, _, _ := Reduce(nil, records, inScope(t))
	if len(findings) != 0 {
		t.Errorf("no name finding behind a wildcard: %+v", findings)
	}
	listed := entries(findings, groups)
	if len(listed) != 4 {
		t.Errorf("the probe is not a result, every other name is: %v", listed)
	}
	for _, g := range groups {
		wild := g.Wildcard == "*.w.example.com"
		if wild != (len(g.Locations) == 3) {
			t.Errorf("group %+v", g)
		}
	}
}

func TestWildcardCNAMEMatchesOnTheChain(t *testing.T) {
	records := []dnsx.Record{
		rec("a.shop.example.com", "NOERROR", []string{"198.51.100.1"}, "shops.example.net"),
		rec(dnsx.ProbePrefix+"1.shop.example.com", "NOERROR", []string{"198.51.100.2"}, "shops.example.net"),
	}
	_, groups, _, _ := Reduce(nil, records, inScope(t))
	if len(groups) != 1 || groups[0].Wildcard != "*.shop.example.com" {
		t.Errorf("a CDN answers with other IPs; the CNAME chain decides: %+v", groups)
	}
}

func TestWildcardParents(t *testing.T) {
	var records []dnsx.Record
	for i := 0; i < 5; i++ {
		records = append(records, rec(fmt.Sprintf("n%d.w.example.com", i), "NOERROR", []string{"192.0.2.9"}))
		records = append(records, rec(fmt.Sprintf("n%d.example.com", i), "NOERROR", []string{"192.0.2.1"}))
		records = append(records, rec(fmt.Sprintf("d%d.dead.example.com", i), "NXDOMAIN", nil))
	}
	records = append(records, rec("other.v.example.com", "NOERROR", []string{"192.0.2.9"}))
	got := strings.Join(WildcardParents(records, []string{"example.com"}, 5), ",")
	if got != "example.com,w.example.com" {
		t.Errorf("parents = %s (dead names and small parents are not probed)", got)
	}
	if p := WildcardParents(records, []string{"w.example.com"}, 5); strings.Join(p, ",") != "w.example.com" {
		t.Errorf("nothing above a root is probed: %v", p)
	}
}

func TestOutOfScopeIsDroppedAndCounted(t *testing.T) {
	hosts := []subfinder.Result{{Host: "a.example.com"}, {Host: "a.example.org"}, {Host: "b.example.org"}}
	records := []dnsx.Record{rec("a.example.org", "NOERROR", []string{"192.0.2.1"})}
	findings, groups, omitted, _ := Reduce(hosts, records, inScope(t))
	if omitted["out_of_scope"] != 2 || len(entries(findings, groups)) != 1 {
		t.Errorf("omitted = %v, listed = %v", omitted, entries(findings, groups))
	}
}

func TestTagsAndSeverity(t *testing.T) {
	tests := []struct {
		a     schema.Answer
		name  bool
		tags  string
		sev   string
		title string
	}{
		{schema.Answer{Status: "NXDOMAIN", CNAME: []string{"x.herokuapp.com"}}, false, "dangling,third-party", "high", "Dangling CNAME to Heroku"},
		{schema.Answer{Status: "NXDOMAIN", CNAME: []string{"gone.example.net"}}, false, "dangling", "medium", "Dangling CNAME to gone.example.net"},
		{schema.Answer{Status: "NXDOMAIN", CNAME: []string{"d1.cloudfront.net"}}, false, "dangling", "medium", "Dangling CNAME to Amazon CloudFront"},
		{schema.Answer{CNAME: []string{"x.domainkey.example.net"}}, false, "no-address", "low", "CNAME to x.domainkey.example.net without an address"},
		{schema.Answer{Status: "SERVFAIL", CNAME: []string{"bucket.s3.amazonaws.com"}}, false, "no-address,third-party", "medium", "CNAME to Amazon S3 without an address"},
		{schema.Answer{CNAME: []string{"wc.example.net"}, Wildcard: "*.example.com"}, false, "", "", ""},
		{schema.Answer{A: []string{"192.168.1.5"}}, false, "private-ip", "medium", "Private IP in public DNS"},
		{schema.Answer{A: []string{"100.64.1.1"}}, false, "private-ip", "medium", "Private IP in public DNS"},
		{schema.Answer{AAAA: []string{"fd00::1"}}, false, "private-ip", "medium", "Private IP in public DNS"},
		{schema.Answer{A: []string{"100.62.1.1"}}, false, "", "", ""},
		{schema.Answer{A: []string{"127.0.0.1"}}, true, "private-ip,name", "medium", "Private IP in public DNS; Interesting name: dev"},
		{schema.Answer{CNAME: []string{"acme.zendesk.com"}, A: []string{"198.51.100.1"}}, false, "third-party", "low", "CNAME to Zendesk"},
		{schema.Answer{CNAME: []string{"x.edgekey.net"}, A: []string{"198.51.100.1"}}, false, "", "", ""},
		{schema.Answer{A: []string{"198.51.100.1"}}, false, "", "", ""},
	}
	for _, tt := range tests {
		if p, ok := Provider(tt.a.CNAME); ok {
			tt.a.Provider = p.name
		}
		tags := Tags(tt.a, tt.name)
		if strings.Join(tags, ",") != tt.tags {
			t.Errorf("%+v: tags %v, want %s", tt.a, tags, tt.tags)
			continue
		}
		if len(tags) == 0 {
			continue
		}
		if s := Severity(tt.a, tags); s != tt.sev {
			t.Errorf("%+v: severity %s, want %s", tt.a, s, tt.sev)
		}
		if s := Title(tt.a, tags, []string{"dev"}); s != tt.title {
			t.Errorf("%+v: title %q, want %q", tt.a, s, tt.title)
		}
	}
}

func TestWords(t *testing.T) {
	tests := map[string]string{
		"dev.example.com":               "dev",
		"api-staging2.eu.example.com":   "staging",
		"jenkins01.ci.example.com":      "ci,jenkins",
		"www.example.com":               "",
		"admin.com":                     "",
		"gitlab.ops.gitlab.com":         "",
		"devops.example.com":            "",
		"pre-prod.example.com":          "pre-prod",
		"k8s.example.com":               "k8s",
		"my_vault.internal.example.com": "internal,vault",
	}
	for name, want := range tests {
		if got := strings.Join(Words(name), ","); got != want {
			t.Errorf("Words(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestRanking(t *testing.T) {
	records := []dnsx.Record{
		rec("dev.example.com", "NOERROR", []string{"192.0.2.1"}),
		rec("mail.example.com", "NOERROR", []string{"192.0.2.2"}, "x.sendgrid.net"),
		rec("mail2.example.com", "NOERROR", []string{"192.0.2.3"}, "y.sendgrid.net"),
		rec("lan.example.com", "NOERROR", []string{"10.1.1.1"}),
		rec("docs.example.com", "NXDOMAIN", nil, "a.github.io"),
	}
	findings, _, _, _ := Reduce(nil, records, inScope(t))
	var order []string
	for _, f := range findings {
		order = append(order, f.Locations[0])
	}
	// severity, then confidence (matched before heuristic), then count, then id
	if got := strings.Join(order, ","); !strings.HasPrefix(got, "docs.example.com,lan.example.com,") || !strings.HasSuffix(got, ",dev.example.com") {
		t.Errorf("order = %s", got)
	}
	again, _, _, _ := Reduce(nil, records, inScope(t))
	for i := range findings {
		if findings[i].ID != again[i].ID {
			t.Errorf("the same input gives the same order and IDs: %s vs %s", findings[i].ID, again[i].ID)
		}
	}
}

func TestDeadGroupsComeLast(t *testing.T) {
	var records []dnsx.Record
	for i := 0; i < 10; i++ {
		records = append(records, rec(fmt.Sprintf("d%d.example.com", i), "NXDOMAIN", nil))
	}
	records = append(records, rec("www.example.com", "NOERROR", []string{"192.0.2.1"}))
	_, groups, _, _ := Reduce(nil, records, inScope(t))
	if len(groups) != 2 || groups[0].Status != "" {
		t.Errorf("a name that resolves ranks before 10 dead names, so the budget cuts dead names first: %+v", groups)
	}
}

func TestFitCutsLeastImportantFirstAndCountsEverything(t *testing.T) {
	res := &schema.Result{Omitted: map[string]int{}, Budget: schema.Budget{MaxBytes: 3000}}
	var locs []string
	for i := 0; i < 20; i++ {
		locs = append(locs, fmt.Sprintf("host%02d.example.com", i))
	}
	for i := 0; i < 5; i++ {
		res.Findings = append(res.Findings, schema.Finding{ID: fmt.Sprintf("name-%d", i), Severity: "low", Tags: []string{"name"}, Locations: locs, Count: len(locs)})
	}
	res.Groups = []schema.Group{{ID: "nxdomain-x", Answer: schema.Answer{Status: "NXDOMAIN"}, Locations: locs, Count: len(locs)}}

	Fit(res, 3000)
	b, _ := schema.Marshal(res)
	if len(b) > 3000 {
		t.Errorf("size %d > 3000", len(b))
	}
	if !res.Budget.Truncated {
		t.Error("truncation not reported")
	}
	if len(res.Groups) == 1 && res.Groups[0].Locations != nil {
		t.Error("group locations should go before any finding data")
	}
	if len(res.Findings) == 0 || len(res.Findings[0].Locations) != 20 {
		t.Errorf("the top finding should keep its locations while lower data can be cut: %+v", res.Findings)
	}
	if !strings.Contains(string(b), `"count":20`) {
		t.Errorf("a finding or group that lost locations must show its count: %s", b)
	}
	shown := 0
	for _, f := range res.Findings {
		shown += len(f.Locations)
	}
	for _, g := range res.Groups {
		shown += len(g.Locations)
	}
	cutFindings := 5 - len(res.Findings)
	cutGroups := 1 - len(res.Groups)
	if res.Omitted["findings"] != cutFindings || res.Omitted["groups"] != cutGroups {
		t.Errorf("omitted = %v, cut %d findings and %d groups", res.Omitted, cutFindings, cutGroups)
	}
	if res.Omitted["locations"]+shown < 20*len(res.Findings)+20*len(res.Groups) {
		t.Errorf("locations not accounted for: omitted=%v shown=%d", res.Omitted, shown)
	}
}
