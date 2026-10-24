package subfinder

import (
	"strings"
	"testing"
)

func TestArgs(t *testing.T) {
	got := strings.Join(Args("roots.txt", Options{Timeout: 20, MaxTime: 3, Extra: []string{"-all"}}), " ")
	want := "-dL roots.txt -json -cs -silent -nc -duc -timeout 20 -max-time 3 -all"
	if got != want {
		t.Errorf("got  %s\nwant %s", got, want)
	}
}

func TestParseReadsJSONAndTextAndSkipsDnsx(t *testing.T) {
	in := strings.Join([]string{
		`{"host":"a.example.com","input":"example.com","sources":["crtsh","anubis"]}`,
		`{"host":"b.example.com","input":"example.com","source":"crtsh"}`,
		`c.example.com`,
		`[INF] Enumerating subdomains for example.com`,
		`{"host":"a.example.com","status_code":"NOERROR","a":["192.0.2.1"]}`,
		`{"host":"d.example.com","ttl":300,"resolver":["1.1.1.1:53"]}`,
		`m.design-staging.example.com","input":"example.com"}`,
		`{"host":`,
		``,
	}, "\n")
	res, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, r := range res {
		got = append(got, r.Host+"="+strings.Join(r.Sources, "+"))
	}
	if strings.Join(got, " ") != "a.example.com=crtsh+anubis b.example.com=crtsh c.example.com=" {
		t.Errorf("got %v", got)
	}
}
