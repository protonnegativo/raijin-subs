package dnsx

import (
	"os"
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	got := strings.Join(Args("names.txt", Options{Rate: 50, Threads: 10, Resolvers: "1.1.1.1"}), " ")
	want := "-l names.txt -a -aaaa -resp -json -silent -nc -duc -omit-raw -rcode noerror,formerr,servfail,nxdomain,notimp,refused -rl 50 -t 10 -r 1.1.1.1"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestParseSkipsSubfinderLines(t *testing.T) {
	in := strings.Join([]string{
		`{"host":"a.example.com","input":"example.com","sources":["crtsh"]}`,
		`{"host":"a.example.com","ttl":300,"a":["192.0.2.1"],"cname":["x.example.net"],"status_code":"NOERROR"}`,
		`{"host":"b.example.com","status_code":"NXDOMAIN"}`,
		`a.example.com [A] [192.0.2.1]`,
		`{"host":"c.example.com","a":"not-a-list","status_code":"NOERROR"}`,
	}, "\n")
	recs, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].A[0] != "192.0.2.1" || recs[0].CNAME[0] != "x.example.net" || recs[1].StatusCode != "NXDOMAIN" {
		t.Errorf("got %+v", recs)
	}
}

func TestProbeName(t *testing.T) {
	n := ProbeName("example.com")
	if !strings.HasPrefix(n, ProbePrefix) || !strings.HasSuffix(n, ".example.com") || len(n) != len(ProbePrefix)+8+len(".example.com") {
		t.Errorf("probe name %q", n)
	}
	if !(Record{Host: n}).Probe() || (Record{Host: "www.example.com"}).Probe() {
		t.Error("Probe() must recognise probe names only")
	}
	if ProbeName("example.com") == n {
		t.Error("probe names are random")
	}
}

func TestMissing(t *testing.T) {
	recs := []Record{{Host: "a.example.com", StatusCode: "NOERROR"}, {Host: "B.example.com.", StatusCode: "NXDOMAIN"}}
	if n := Missing([]string{"a.example.com", "b.example.com", "c.example.com", "C.example.com", ""}, recs); n != 1 {
		t.Errorf("Missing = %d, want 1", n)
	}
}

// The drift job's NXDOMAIN check must run dnsx exactly as Run does, or it would test something else.
func TestDriftJobUsesTheSameArgs(t *testing.T) {
	b, err := os.ReadFile("../../.github/workflows/engine-drift.yml")
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Join(Args("LIST", Options{}), " ")
	if want := strings.Replace(args, "LIST", `"$RUNNER_TEMP/nx.txt"`, 1); !strings.Contains(string(b), "dnsx "+want+" ") {
		t.Errorf("engine-drift.yml must run dnsx %s", want)
	}
}
