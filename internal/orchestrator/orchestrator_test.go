package orchestrator

import (
	"testing"

	"github.com/apophis-eng/apophis/internal/models"
)

func TestBuildStrategies_LenMatch(t *testing.T) {
	for _, n := range []int{1, 3, 6, 10, 20} {
		s := buildStrategies(n)
		if len(s) != n {
			t.Errorf("buildStrategies(%d) returned %d strategies", n, len(s))
		}
	}
}

func TestBuildStrategies_Diversity(t *testing.T) {
	s := buildStrategies(6)
	seen := map[models.Strategy]bool{}
	for _, x := range s {
		seen[x] = true
	}
	if len(seen) < 4 {
		t.Errorf("expected at least 4 distinct strategies in 6-agent pool, got %d", len(seen))
	}
}

func TestMergeAndDedupe_PreservesHighestSeverity(t *testing.T) {
	findings := []models.Finding{
		{Category: "CVE", Target: "a", Title: "X", Port: 80, Severity: models.SeverityLow, CVSS: 4.0},
		{Category: "CVE", Target: "a", Title: "X", Port: 80, Severity: models.SeverityHigh, CVSS: 9.0},
		{Category: "CVE", Target: "b", Title: "Y", Port: 443, Severity: models.SeverityCritical, CVSS: 10.0},
	}
	deduped := mergeAndDedupe(findings)
	if len(deduped) != 2 {
		t.Fatalf("expected 2 deduped findings, got %d", len(deduped))
	}
	if deduped[0].Severity != models.SeverityCritical {
		t.Errorf("expected first finding to be CRITICAL, got %s", deduped[0].Severity)
	}
	if deduped[0].CVSS != 10.0 {
		t.Errorf("expected first finding CVSS 10.0, got %.1f", deduped[0].CVSS)
	}
}

func TestBuildSummary(t *testing.T) {
	findings := []models.Finding{
		{Severity: models.SeverityCritical},
		{Severity: models.SeverityCritical},
		{Severity: models.SeverityHigh},
		{Severity: models.SeverityMedium},
		{Severity: models.SeverityInfo},
	}
	s := buildSummary(findings)
	if s.Critical != 2 || s.High != 1 || s.Medium != 1 || s.Info != 1 {
		t.Errorf("summary count wrong: %+v", s)
	}
	if s.RiskScore < 20+7+4 {
		t.Errorf("risk score too low: %d", s.RiskScore)
	}
}
