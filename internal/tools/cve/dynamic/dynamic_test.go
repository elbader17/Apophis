package dynamic

import (
	"os"
	"testing"
	"time"
)

func TestStoreAddAndSearch(t *testing.T) {
	dir, _ := os.MkdirTemp("", "dyntest")
	defer os.RemoveAll(dir)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	added, _ := s.Add([]Entry{
		{CVE: "CVE-2024-1001", Service: "log4j", Version: "2.14.0", Severity: "CRITICAL", CVSS: 10, Title: "Test", HasKEV: true, Published: now},
		{CVE: "CVE-2024-1002", Service: "apache", Version: "2.4.7", Severity: "HIGH", CVSS: 7.5, Title: "X", Published: now.Add(-48 * time.Hour)},
		{CVE: "CVE-2024-1003", Service: "ssh", Version: "OpenSSH_6", Severity: "LOW", CVSS: 3.0, Title: "Y", Published: now.Add(-100 * time.Hour)},
	})
	if added != 3 {
		t.Errorf("expected 3 added, got %d", added)
	}
	if s.Len() != 3 {
		t.Errorf("expected 3 stored, got %d", s.Len())
	}

	res := s.Search(SearchQuery{Keyword: "log4j"})
	if len(res) != 1 || res[0].CVE != "CVE-2024-1001" {
		t.Errorf("keyword search wrong: %+v", res)
	}

	res = s.Search(SearchQuery{MinCVSS: 7.0})
	if len(res) != 2 {
		t.Errorf("min_cvss search wrong: got %d", len(res))
	}

	res = s.Search(SearchQuery{OnlyKEV: true})
	if len(res) != 1 || res[0].CVE != "CVE-2024-1001" {
		t.Errorf("only_kev wrong: %+v", res)
	}

	since := now.Add(-72 * time.Hour)
	res = s.Search(SearchQuery{Since: &since})
	if len(res) != 2 {
		t.Errorf("since search wrong: got %d", len(res))
	}
}

func TestStoreDedup(t *testing.T) {
	dir, _ := os.MkdirTemp("", "dyntest")
	defer os.RemoveAll(dir)
	s, _ := Open(dir)
	added, updated := s.Add([]Entry{
		{CVE: "CVE-2024-2001", Service: "x", CVSS: 5.0, Severity: "MEDIUM"},
	})
	if added != 1 {
		t.Fatalf("expected 1 added, got %d", added)
	}
	added, updated = s.Add([]Entry{
		{CVE: "CVE-2024-2001", Service: "x", CVSS: 9.5, Severity: "CRITICAL", HasKEV: true, Description: "better"},
	})
	if added != 0 {
		t.Errorf("expected 0 added on dedup, got %d", added)
	}
	if updated != 1 {
		t.Errorf("expected 1 updated, got %d", updated)
	}
	if s.All()[0].CVSS != 9.5 {
		t.Errorf("dedup didn't pick higher CVSS")
	}
}

func TestStorePersistence(t *testing.T) {
	dir, _ := os.MkdirTemp("", "dyntest")
	defer os.RemoveAll(dir)
	s, _ := Open(dir)
	s.Add([]Entry{{CVE: "CVE-X", Service: "y", CVSS: 8.0, Severity: "HIGH"}})

	s2, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Len() != 1 {
		t.Errorf("expected persistence, got %d", s2.Len())
	}
}
