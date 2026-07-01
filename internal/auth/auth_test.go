package auth

import (
	"testing"

	"github.com/apophis-eng/apophis/internal/models"
)

func TestEnumerateDelegationUnconstrained(t *testing.T) {
	uac := map[string]int{
		"DC01$":        0x80000, // TRUSTED_FOR_DELEGATION
		"webserver01$": 0x80000,
		"normaluser":   0x0,
	}
	attrs := map[string]map[string][]string{}
	got := EnumerateDelegation(uac, attrs)
	if len(got) != 2 {
		t.Fatalf("expected 2 unconstrained entries, got %d", len(got))
	}
	for _, d := range got {
		if d.Type != DelUnconstrained {
			t.Fatalf("expected unconstrained, got %s", d.Type)
		}
	}
}

func TestEnumerateDelegationConstrained(t *testing.T) {
	uac := map[string]int{"svc-sql": 0x0}
	attrs := map[string]map[string][]string{
		"svc-sql": {
			"msDS-AllowedToDelegateTo": {"MSSQLSvc/db01.corp.local", "ldap/dc01.corp.local"},
		},
	}
	got := EnumerateDelegation(uac, attrs)
	if len(got) != 1 {
		t.Fatalf("expected 1 constrained entry, got %d", len(got))
	}
	if got[0].Type != DelConstrained {
		t.Fatalf("expected constrained, got %s", got[0].Type)
	}
	if len(got[0].Targets) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(got[0].Targets))
	}
}

func TestEnumerateDelegationRBCD(t *testing.T) {
	uac := map[string]int{"web01": 0x0}
	attrs := map[string]map[string][]string{
		"web01": {
			"msDS-AllowedToActOnBehalfOfOtherIdentity": {"O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-...)"},
		},
	}
	got := EnumerateDelegation(uac, attrs)
	if len(got) != 1 || got[0].Type != DelRBCD {
		t.Fatalf("expected 1 RBCD entry, got %+v", got)
	}
}

func TestDelegationToFindingsEmpty(t *testing.T) {
	if f := DelegationToFindings("x", nil); len(f) != 0 {
		t.Fatalf("expected no findings for empty input")
	}
}

func TestDelegationToFindingsDCDetected(t *testing.T) {
	in := []DelegationTarget{{Account: "DC01$", Type: DelUnconstrained, IsDC: true}}
	f := DelegationToFindings("AD", in)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != models.SeverityCritical {
		t.Fatalf("DC unconstrained should be critical, got %s", f[0].Severity)
	}
}

func TestPasswordPolicyRiskScore(t *testing.T) {
	cases := []struct {
		name string
		p    *PasswordPolicy
		min  int
		max  int
	}{
		{"strong", &PasswordPolicy{MinPasswordLength: 14, LockoutThreshold: 10, PasswordComplexity: true, MaxPasswordAgeDays: 60}, 0, 0},
		{"weak-nolock", &PasswordPolicy{MinPasswordLength: 7, LockoutThreshold: 0}, 60, 200},
		{"weak-only-length", &PasswordPolicy{MinPasswordLength: 7, LockoutThreshold: 10, PasswordComplexity: true, MaxPasswordAgeDays: 60}, 15, 60},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			score, _ := c.p.RiskScore()
			if score < c.min || score > c.max {
				t.Errorf("%s: score %d not in [%d, %d]", c.name, score, c.min, c.max)
			}
		})
	}
}

func TestParseDomainPolicy(t *testing.T) {
	p := ParseDomainPolicy(map[string][]string{
		"minPwdLength":             {"8"},
		"lockoutThreshold":         {"10"},
		"maxPwdAge":                {"864000000000"},
		"pwdProperties":            {"1"},
		"lockoutDuration":          {"900000000"},
		"lockoutObservationWindow": {"900000000"},
	})
	if p.MinPasswordLength != 8 {
		t.Errorf("minPwdLength=%d", p.MinPasswordLength)
	}
	if p.LockoutThreshold != 10 {
		t.Errorf("lockoutThreshold=%d", p.LockoutThreshold)
	}
	if !p.PasswordComplexity {
		t.Error("complexity should be true")
	}
}

func TestSprayWordlistCompanyMutations(t *testing.T) {
	words := GenerateSprayWords(SprayConfig{Company: "acme"})
	if len(words) < 10 {
		t.Fatalf("expected >= 10 words, got %d", len(words))
	}
	// Check acme is in there.
	found := false
	for _, w := range words {
		if w.Word == "acme" || w.Word == "Acme" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected acme / Acme in wordlist")
	}
}

func TestSprayDomainDerivesCompany(t *testing.T) {
	words := GenerateSprayWords(SprayConfig{Domain: "corp.local"})
	found := false
	for _, w := range words {
		if w.Word == "corp" || w.Word == "Corp" {
			found = true
		}
	}
	if !found {
		t.Fatal("expected corp / Corp in wordlist from Domain")
	}
}

func TestSprayDedup(t *testing.T) {
	words := GenerateSprayWords(SprayConfig{Company: "acme", Include: []string{"acme"}})
	seen := map[string]bool{}
	for _, w := range words {
		if seen[w.Word] {
			t.Fatalf("duplicate word in wordlist: %q", w.Word)
		}
		seen[w.Word] = true
	}
}

func TestFProducesCategorisedFinding(t *testing.T) {
	f := F(VectorASREPRoast, "t", "host", models.SeverityHigh, "e", "d", "x", "r")
	if f.Category != "AuthAttack" {
		t.Errorf("category=%s", f.Category)
	}
	if len(f.Tags) < 2 {
		t.Errorf("expected at least 2 tags, got %v", f.Tags)
	}
}

func TestKerberoastTargetListToFindingsEmpty(t *testing.T) {
	var l KerberoastTargetList
	if f := l.ToFindings("x"); len(f) != 0 {
		t.Fatalf("expected no findings for empty list, got %d", len(f))
	}
}

func TestRankKerberoastTargetsEmpty(t *testing.T) {
	got := RankKerberoastTargets(nil)
	if len(got) != 0 {
		t.Fatalf("expected empty, got %d", len(got))
	}
}

func TestRankKerberoastTargetsRanksByDifficulty(t *testing.T) {
	// FileTime for 2025-01-01 in 100ns ticks since 1601-01-01: ~134000 days
	// × 86400 × 10^7 = 115776000000000000.
	oldPasswordFT := "115776000000000000"
	newPasswordFT := "138000000000000000" // much later → recent
	in := []SPNService{
		{Account: "b", SPN: "x/b", Enabled: true, PasswordLastSet: oldPasswordFT},                   // old → low
		{Account: "a", SPN: "x/a", Enabled: true, PasswordLastSet: newPasswordFT, AdminCount: true}, // recent + admin → high
	}
	got := RankKerberoastTargets(in)
	if len(got) != 2 {
		t.Fatalf("expected 2 enabled targets, got %d", len(got))
	}
	if got[0].Account != "b" {
		t.Fatalf("expected b (low difficulty) first, got %s (notes=%s)", got[0].Account, got[0].Notes)
	}
	if got[1].Account != "a" {
		t.Fatalf("expected a (high difficulty) second, got %s (notes=%s)", got[1].Account, got[1].Notes)
	}
}
