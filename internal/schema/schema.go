// Package schema defines the Raijin Schema, the JSON shape every Raijin tool returns.
//
// Nothing the engines found is dropped silently: every subdomain is listed, in a finding or in a group,
// and anything a budget cuts is counted in Omitted. What an agent can rebuild is left out of the JSON to
// save tokens: empty lists, the budget when nothing was cut, a count equal to the locations listed, and
// fields at their documented default.
//
// raijin-subs adds the DNS answer (status, cname, a, aaaa, provider, wildcard) to findings and groups:
// it is what an agent reads to pick its next targets.
package schema

import core "github.com/protonnegativo/raijin-core/schema"

// The envelope (Result, Error, Budget, Marshal and the ranks) lives in raijin-core; this tool adds its
// own Finding and Group.
type (
	Result = core.Result[Finding, Group]
	Error  = core.Error
	Budget = core.Budget
)

var (
	Marshal        = core.Marshal
	Write          = core.Write
	SeverityRank   = core.SeverityRank
	ConfidenceRank = core.ConfidenceRank
)

// Answer is what every name in a finding or group resolved to. Zero values are left out: no status
// means NOERROR with at least one record, no cname means the name has no CNAME, no a or aaaa means no
// record of that type.
type Answer struct {
	// Status is the DNS status when it is not NOERROR with records: NXDOMAIN, SERVFAIL, REFUSED...,
	// NODATA (NOERROR without A, AAAA or CNAME), NOANSWER (dnsx returned nothing for the name) or
	// UNCHECKED (dnsx did not run).
	Status string `json:"status,omitempty"`
	// CNAME is the chain, in the order the resolver returned it.
	CNAME []string `json:"cname,omitempty"`
	A     []string `json:"a,omitempty"`
	AAAA  []string `json:"aaaa,omitempty"`
	// Provider is the third-party service the CNAME chain points into, when it is a known one.
	Provider string `json:"provider,omitempty"`
	// Wildcard is the wildcard ("*.example.com") that answers for these names: a random name under
	// it resolved to the same answer, so the names may not exist on their own.
	Wildcard string `json:"wildcard,omitempty"`
}

// Finding is one answer worth a look (a dangling CNAME, a private IP, a third-party service, a name like
// dev or vpn) with every name that has it.
// The same tool and ID in two runs is the same finding.
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	// Confidence is "verified" or "heuristic"; empty means "matched".
	Confidence string `json:"confidence,omitempty"`
	// Tags are the rules that made it a finding: dangling, private-ip, no-address, third-party, name.
	Tags []string `json:"tags"`
	Answer
	// Locations are every name with this answer.
	Locations []string `json:"locations"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
	// Fingerprint is the internal key for --state; it is derived from the ID and not written.
	Fingerprint string `json:"-"`
	New         bool   `json:"new,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (f Finding) MarshalJSON() ([]byte, error) {
	type plain Finding
	p := plain(f)
	p.Count = core.OmitCount(p.Count, len(p.Locations))
	return Marshal(p)
}

// Group is one answer that no rule flagged (names behind the same IPs, names that do not resolve), with
// every name that has it. 50 names behind the same two load balancer IPs are one group.
type Group struct {
	ID string `json:"id"`
	Answer
	Locations []string `json:"locations,omitempty"`
	// Count is the number of locations; it is written only when the budget cut Locations.
	Count int `json:"count,omitempty"`
}

// MarshalJSON leaves out count when every location is listed.
func (g Group) MarshalJSON() ([]byte, error) {
	type plain Group
	p := plain(g)
	p.Count = core.OmitCount(p.Count, len(p.Locations))
	return Marshal(p)
}
