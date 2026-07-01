package planner

import (
	"testing"

	"github.com/apophis-eng/apophis/internal/models"
)

func TestRuleBasedAlwaysIncludesRecon(t *testing.T) {
	r := NewRuleBased()
	plan := r.Plan(models.TargetProfile{Host: "x"})
	hasRecon := false
	for _, s := range plan.Strategies {
		if s == models.StrategyRecon {
			hasRecon = true
		}
	}
	if !hasRecon {
		t.Fatalf("recon must always be in the plan: %v", plan.Strategies)
	}
}

func TestRuleBasedAddsWebFocusForHTTP(t *testing.T) {
	r := NewRuleBased()
	plan := r.Plan(models.TargetProfile{Host: "x", HasWeb: true})
	hasWeb := false
	for _, s := range plan.Strategies {
		if s == models.StrategyWebFocus {
			hasWeb = true
		}
	}
	if !hasWeb {
		t.Fatalf("web focus expected when HTTP detected: %v", plan.Strategies)
	}
}

func TestRuleBasedAddsStealthForWAF(t *testing.T) {
	r := NewRuleBased()
	plan := r.Plan(models.TargetProfile{Host: "x", HasWeb: true, WAF: "cloudflare"})
	hasStealth := false
	for _, s := range plan.Strategies {
		if s == models.StrategyStealth {
			hasStealth = true
		}
	}
	if !hasStealth {
		t.Fatalf("stealth expected when WAF detected: %v", plan.Strategies)
	}
}

func TestRuleBasedCapsAtSix(t *testing.T) {
	r := NewRuleBased()
	p := models.TargetProfile{
		Host: "x", HasWeb: true, WAF: "cloudflare",
		OpenPorts: []int{21, 22, 25, 80, 443, 445, 3306},
		ServiceBanners: []string{
			"smb", "ssh", "ldap", "snmp", "rdp", "telnet", "vnc",
		},
	}
	plan := r.Plan(p)
	if len(plan.Strategies) > 6 {
		t.Fatalf("plan should be capped at 6 strategies, got %d: %v", len(plan.Strategies), plan.Strategies)
	}
}

func TestRuleBasedRationaleNotEmpty(t *testing.T) {
	r := NewRuleBased()
	plan := r.Plan(models.TargetProfile{Host: "x", HasWeb: true})
	if len(plan.Rationale) == 0 {
		t.Fatalf("expected rationale entries to explain picks")
	}
}

func TestUniqStrategies(t *testing.T) {
	in := []models.Strategy{
		models.StrategyRecon, models.StrategyRecon, models.StrategyAggressive,
	}
	out := uniqStrategies(in)
	if len(out) != 2 {
		t.Fatalf("expected 2 unique, got %d: %v", len(out), out)
	}
}
