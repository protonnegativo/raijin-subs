package schema

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDerivableFieldsAreLeftOut(t *testing.T) {
	res := Result{
		Tool:     "raijin-subs",
		Findings: []Finding{{ID: "name-ab12cd34", Title: "Interesting name", Severity: "low", Tags: []string{"name"}, Answer: Answer{A: []string{"192.0.2.1"}}, Locations: []string{"dev.example.com", "vpn.example.com"}, Count: 2, Fingerprint: "fp"}},
		Groups:   []Group{{ID: "a-ef56ab78", Answer: Answer{A: []string{"192.0.2.2"}}, Locations: []string{"www.example.com"}, Count: 1}},
		Omitted:  map[string]int{},
		Errors:   []Error{},
		Next:     []string{},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000},
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"fingerprint", "count", "confidence", "status", "cname", "aaaa", "provider", "wildcard", "new", "omitted", "errors", "next", "raw", "budget"} {
		if strings.Contains(string(b), `"`+k+`"`) {
			t.Errorf("%s should be left out: %s", k, b)
		}
	}
	if strings.Contains(string(b), "null") {
		t.Errorf("no null values: %s", b)
	}
}

func TestAnswerFieldsAreInline(t *testing.T) {
	f := Finding{ID: "dangling-x", Title: "Dangling CNAME to GitHub Pages", Severity: "high", Tags: []string{"dangling", "third-party"}, Answer: Answer{Status: "NXDOMAIN", CNAME: []string{"acme.github.io"}, Provider: "GitHub Pages"}, Locations: []string{"docs.example.com"}}
	b, _ := json.Marshal(f)
	want := `{"id":"dangling-x","title":"Dangling CNAME to GitHub Pages","severity":"high","tags":["dangling","third-party"],"status":"NXDOMAIN","cname":["acme.github.io"],"provider":"GitHub Pages","locations":["docs.example.com"]}`
	if string(b) != want {
		t.Errorf("got  %s\nwant %s", b, want)
	}
}

func TestCountAndBudgetAppearWhenSomethingIsCut(t *testing.T) {
	res := Result{
		Findings: []Finding{{ID: "name-x", Tags: []string{"name"}, Locations: []string{"dev.example.com"}, Count: 7}},
		Groups:   []Group{{ID: "nodata-y", Count: 4}},
		Budget:   Budget{MaxItems: 20, MaxBytes: 8000, Truncated: true},
	}
	b, _ := json.Marshal(res)
	s := string(b)
	if !strings.Contains(s, `"locations":["dev.example.com"],"count":7`) || !strings.Contains(s, `{"id":"nodata-y","count":4}`) {
		t.Errorf("count must be written when locations were cut: %s", s)
	}
	if !strings.Contains(s, `"budget":{"max_items":20,"max_bytes":8000,"truncated":true}`) || strings.Count(s, "budget") != 1 {
		t.Errorf("budget must be written once when something was cut: %s", s)
	}
}
