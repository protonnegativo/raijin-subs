package dnsx

import (
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	got := strings.Join(Args("names.txt", Options{Rate: 50, Threads: 10, Resolvers: "1.1.1.1"}), " ")
	want := "-l names.txt -a -aaaa -cname -resp -json -silent -nc -duc -omit-raw -rcode noerror,formerr,servfail,nxdomain,notimp,refused -rl 50 -t 10 -r 1.1.1.1"
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
