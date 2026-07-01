package nuclei

import (
	"testing"
)

func TestParseSimpleTemplate(t *testing.T) {
	yaml := `id: test-template
info:
  name: Test Template
  author: apophis
  severity: high
  description: A test template
http:
  - method: GET
    path:
      - "{{base}}/.git/config"
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "[core]"
        condition: and
`
	tmpl, err := Parse(yaml)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if tmpl.ID != "test-template" {
		t.Fatalf("expected id=test-template, got %q", tmpl.ID)
	}
	if tmpl.Info.Name != "Test Template" {
		t.Fatalf("expected info.name=Test Template, got %q", tmpl.Info.Name)
	}
	if tmpl.Info.Severity != "high" {
		t.Fatalf("expected severity=high, got %q", tmpl.Info.Severity)
	}
	if len(tmpl.Requests) != 1 {
		t.Fatalf("expected 1 http request, got %d", len(tmpl.Requests))
	}
	h := tmpl.Requests[0]
	if h.Method != "GET" {
		t.Fatalf("expected method=GET, got %q", h.Method)
	}
	if len(h.Path) != 1 || h.Path[0] != "{{base}}/.git/config" {
		t.Fatalf("unexpected path: %v", h.Path)
	}
	if len(h.Matchers) != 2 {
		t.Fatalf("expected 2 matchers, got %d", len(h.Matchers))
	}
	if h.Matchers[0].Type != "status" {
		t.Fatalf("expected first matcher to be status, got %q", h.Matchers[0].Type)
	}
	if h.Matchers[0].Status[0] != 200 {
		t.Fatalf("expected status=200, got %d", h.Matchers[0].Status[0])
	}
}

func TestParseMultiRequest(t *testing.T) {
	yaml := `id: multi
info:
  name: Multi
  severity: medium
http:
  - method: GET
    path:
      - "/a"
      - "/b"
  - method: POST
    path:
      - "/c"
    body: "key=value"
`
	tmpl, err := Parse(yaml)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	if len(tmpl.Requests) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(tmpl.Requests))
	}
	if len(tmpl.Requests[0].Path) != 2 {
		t.Fatalf("expected 2 paths in first request, got %d", len(tmpl.Requests[0].Path))
	}
	if tmpl.Requests[1].Body != "key=value" {
		t.Fatalf("expected body in second request, got %q", tmpl.Requests[1].Body)
	}
}

func TestParseHeaders(t *testing.T) {
	yaml := `id: hdr
info:
  name: Header Test
  severity: low
http:
  - method: GET
    path:
      - "/"
    headers:
      X-Token: abc
      User-Agent: probe
`
	tmpl, err := Parse(yaml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	headers := tmpl.Requests[0].Headers
	if len(headers) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(headers))
	}
}

func TestParseQuotedString(t *testing.T) {
	yaml := `id: q
info:
  name: 'Quoted: with colon'
  severity: high
http:
  - method: GET
    path:
      - "/"
`
	tmpl, err := Parse(yaml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if tmpl.Info.Name != "Quoted: with colon" {
		t.Fatalf("expected quoted name preserved, got %q", tmpl.Info.Name)
	}
}

func TestBundledTemplatesParse(t *testing.T) {
	for i, raw := range BundledTemplates {
		if _, err := Parse(raw); err != nil {
			t.Fatalf("bundled template %d failed to parse: %v", i, err)
		}
	}
}

func TestMatchAllAndOr(t *testing.T) {
	ms := []Matcher{
		{Type: "status", Status: []int{200}},
		{Type: "word", Words: []string{"hello"}, Condition: "or"},
	}
	// OR: at least one matches.
	if !matchAllCheck(ms, "or", 200, []byte("hello world")) {
		t.Fatal("OR: 200 status alone should match")
	}
	if !matchAllCheck(ms, "or", 404, []byte("hello world")) {
		t.Fatal("OR: word match alone should match")
	}
	if matchAllCheck(ms, "or", 404, []byte("nope")) {
		t.Fatal("OR: no match should not match")
	}
	// AND: all must match.
	if !matchAllCheck(ms, "and", 200, []byte("hello world")) {
		t.Fatal("AND: both should match")
	}
	if matchAllCheck(ms, "and", 200, []byte("nope")) {
		t.Fatal("AND: missing word should not match")
	}
}

func TestNegateMatcher(t *testing.T) {
	m := Matcher{Type: "status", Status: []int{200}, Negate: true}
	if !singleMatchBool(m, 404, nil) {
		t.Fatal("negate: non-matching status should pass")
	}
	if singleMatchBool(m, 200, nil) {
		t.Fatal("negate: matching status should fail")
	}
}

// Helper wrappers (matchAll/matchAllCheck live in different visibility).
func matchAllCheck(ms []Matcher, cond string, status int, body []byte) bool {
	ok, _ := matchAll(ms, cond, status, body)
	return ok
}
func singleMatchBool(m Matcher, status int, body []byte) bool {
	ok, _ := singleMatch(m, status, body)
	return ok
}
