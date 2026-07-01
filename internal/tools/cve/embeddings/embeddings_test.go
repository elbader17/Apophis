package embeddings

import (
	"strings"
	"testing"
	"time"

	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
)

func sampleEntries() []dynamic.Entry {
	return []dynamic.Entry{
		{
			CVE: "CVE-2017-0144", Service: "smb", Version: "*",
			Severity: "CRITICAL", CVSS: 9.3,
			Title:       "SMBv1 Remote Code Execution (EternalBlue)",
			Description: "SMBv1 mishandles crafted packets allowing remote code execution.",
			Published:   time.Now(),
		},
		{
			CVE: "CVE-2021-44228", Service: "*", Version: "log4j",
			Severity: "CRITICAL", CVSS: 10.0,
			Title:       "Log4Shell",
			Description: "Apache Log4j2 JNDI lookup remote code execution",
			Published:   time.Now(),
		},
		{
			CVE: "CVE-2017-5638", Service: "http", Version: "struts2",
			Severity: "CRITICAL", CVSS: 10.0,
			Title:       "Apache Struts2 Content-Type OGNL RCE",
			Description: "Jakarta Multipart parser mishandles Content-Type header",
			Published:   time.Now(),
		},
	}
}

func TestIndexRebuildAndLen(t *testing.T) {
	ix := New()
	ix.Rebuild(sampleEntries())
	if ix.Len() != 3 {
		t.Fatalf("expected 3 entries, got %d", ix.Len())
	}
}

func TestSearchFindsLog4Shell(t *testing.T) {
	ix := New()
	ix.Rebuild(sampleEntries())
	res := ix.Search("log4j JNDI lookup remote code execution", 3)
	if len(res) == 0 {
		t.Fatalf("expected at least 1 result")
	}
	if !strings.Contains(strings.ToLower(res[0].Entry.Title), "log4shell") {
		t.Fatalf("top result should be Log4Shell, got %q", res[0].Entry.Title)
	}
}

func TestSearchFindsEternalBlue(t *testing.T) {
	ix := New()
	ix.Rebuild(sampleEntries())
	res := ix.Search("SMBv1 remote code execution crafted packets", 3)
	if len(res) == 0 {
		t.Fatalf("expected results")
	}
	if !strings.Contains(res[0].Entry.CVE, "CVE-2017-0144") {
		t.Fatalf("top result should be EternalBlue, got %s", res[0].Entry.CVE)
	}
}

func TestSearchNoMatchReturnsEmpty(t *testing.T) {
	ix := New()
	ix.Rebuild(sampleEntries())
	res := ix.Search("zzzqqqxxx nothing relevant here", 5)
	if len(res) != 0 {
		t.Fatalf("expected 0 results for unrelated query, got %d", len(res))
	}
}

func TestSearchEmptyIndexIsSafe(t *testing.T) {
	ix := New()
	ix.Rebuild(nil)
	res := ix.Search("anything", 5)
	if len(res) != 0 {
		t.Fatalf("expected empty results on empty index")
	}
}

func TestTokeniseCVE(t *testing.T) {
	toks := tokenise("CVE-2021-44228 is a log4j RCE")
	if !contains(toks, "cve-2021-44228") {
		t.Fatalf("expected cve id to be tokenised verbatim: %v", toks)
	}
	if !contains(toks, "log4j") {
		t.Fatalf("expected log4j in tokens: %v", toks)
	}
	if !contains(toks, "rce") {
		t.Fatalf("expected rce in tokens: %v", toks)
	}
}

func TestTokeniseStripsStopwords(t *testing.T) {
	toks := tokenise("the quick brown fox jumps over the lazy dog")
	for _, tok := range toks {
		if stop[tok] {
			t.Fatalf("stopword %q leaked into tokens", tok)
		}
	}
}

func contains(s []string, want string) bool {
	for _, x := range s {
		if x == want {
			return true
		}
	}
	return false
}
