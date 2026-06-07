package cve

import (
	"testing"

	"github.com/apophis-eng/apophis/internal/models"
)

func TestCVE_Match_OpenSSH(t *testing.T) {
	m := New()
	findings := m.Match("ssh", "OpenSSH_6.6.1p1", "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13")
	if len(findings) == 0 {
		t.Errorf("expected at least one CVE finding for OpenSSH 6.6.1, got 0")
	}
	for _, f := range findings {
		if f.Severity == "" {
			t.Errorf("finding %q has empty severity", f.Title)
		}
	}
}

func TestCVE_Match_GenericWildcard(t *testing.T) {
	m := New()
	findings := m.Match("anything", "log4j-2.14.0", "log4j-2.14.0")
	if len(findings) == 0 {
		t.Errorf("expected wildcard log4j match")
	}
}

func TestCVE_NoMatch(t *testing.T) {
	m := New()
	findings := m.Match("unknown-service", "1.0", "no banner")
	if len(findings) != 0 {
		t.Errorf("expected no findings for unknown service, got %d", len(findings))
	}
}

func TestCVE_Log4Shell(t *testing.T) {
	m := New()
	findings := m.Match("http", "log4j-2.14.0", "Apache log4j-2.14.0")
	if len(findings) == 0 {
		t.Errorf("expected Log4Shell match for log4j banner")
	}
}

func TestCVE_WildcardSMB(t *testing.T) {
	m := New()
	findings := m.Match("smb", "", "")
	if len(findings) == 0 {
		t.Errorf("expected SMB wildcard CVE matches")
	}
	hasEternalBlue := false
	for _, f := range findings {
		for _, c := range f.CVE {
			if c == "CVE-2017-0144" {
				hasEternalBlue = true
			}
		}
	}
	if !hasEternalBlue {
		t.Errorf("expected EternalBlue (CVE-2017-0144) in findings")
	}
}

func TestCVE_SeverityScoring(t *testing.T) {
	m := New()
	findings := m.Match("rdp", "Windows 7", "")
	for _, f := range findings {
		if f.Severity == models.SeverityCritical && f.CVSS < 9.0 {
			t.Errorf("CRITICAL finding %s has low CVSS %.1f", f.Title, f.CVSS)
		}
	}
}
