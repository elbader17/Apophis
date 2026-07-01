package auth

import (
	"fmt"
	"strings"

	"github.com/apophis-eng/apophis/internal/models"
)

// PasswordPolicy describes the AD domain password policy.
type PasswordPolicy struct {
	MinPasswordLength     int
	PasswordHistory       int
	MaxPasswordAgeDays    int
	MinPasswordAgeDays    int
	LockoutThreshold      int // 0 = no lockout (very dangerous)
	LockoutDurationMin    int
	LockoutObservationMin int
	PasswordComplexity    bool // requires 3 of 5 character classes
	ReversibleEncryption  bool // reversible encryption stored (LM hashes)
}

// ParseDomainPolicy pulls the domain password policy attributes out of an
// LDAP search result map. We accept the raw attribute map so this function
// stays pure and easy to unit-test.
func ParseDomainPolicy(attrs map[string][]string) *PasswordPolicy {
	p := &PasswordPolicy{
		MinPasswordLength:     parseIntAttr(attrs, "minPwdLength", 0),
		PasswordHistory:       parseIntAttr(attrs, "pwdHistoryLength", 0),
		MaxPasswordAgeDays:    parseIntAttr(attrs, "maxPwdAge", 0) / 864000000000, // FILETIME 100ns → days
		MinPasswordAgeDays:    parseIntAttr(attrs, "minPwdAge", 0) / 864000000000,
		LockoutThreshold:      parseIntAttr(attrs, "lockoutThreshold", 0),
		LockoutDurationMin:    parseIntAttr(attrs, "lockoutDuration", 0) / 600000000, // 100ns → minutes
		LockoutObservationMin: parseIntAttr(attrs, "lockoutObservationWindow", 0) / 600000000,
		PasswordComplexity:    hasAttr(attrs, "pwdProperties", "1"),
		ReversibleEncryption:  hasAttr(attrs, "pwdProperties", "0"),
	}
	return p
}

// RiskScore returns a 0–100 grade plus reasons for the report.
func (p *PasswordPolicy) RiskScore() (int, []string) {
	score := 0
	reasons := []string{}
	if p.MinPasswordLength < 8 {
		score += 30
		reasons = append(reasons, fmt.Sprintf("minPwdLength=%d (<8)", p.MinPasswordLength))
	} else if p.MinPasswordLength < 12 {
		score += 15
		reasons = append(reasons, fmt.Sprintf("minPwdLength=%d (<12, modern recommendation is 14+)", p.MinPasswordLength))
	}
	if p.LockoutThreshold == 0 {
		score += 50
		reasons = append(reasons, "lockoutThreshold=0 (no account lockout — password spray is unconstrained)")
	} else if p.LockoutThreshold > 10 {
		score += 10
		reasons = append(reasons, fmt.Sprintf("lockoutThreshold=%d (allows spray with jitter)", p.LockoutThreshold))
	}
	if !p.PasswordComplexity {
		score += 10
		reasons = append(reasons, "passwordComplexity not required")
	}
	if p.MaxPasswordAgeDays == 0 {
		score += 10
		reasons = append(reasons, "passwords never expire")
	}
	if p.ReversibleEncryption {
		score += 30
		reasons = append(reasons, "reversible encryption enabled (LM hashes stored)")
	}
	return score, reasons
}

// ToFindings renders the policy as a finding.
func (p *PasswordPolicy) ToFindings(target string) []models.Finding {
	if p == nil {
		return nil
	}
	score, reasons := p.RiskScore()
	if score == 0 {
		return nil
	}
	sev := models.SeverityLow
	switch {
	case score >= 60:
		sev = models.SeverityCritical
	case score >= 30:
		sev = models.SeverityHigh
	case score >= 15:
		sev = models.SeverityMedium
	}
	return []models.Finding{F(
		VectorWeakPasswordPolicy,
		fmt.Sprintf("Weak AD password policy on %s — score %d", target, score),
		target,
		sev,
		fmt.Sprintf("minPwdLength=%d history=%d lockoutThreshold=%d complexity=%v maxAge=%dd", p.MinPasswordLength, p.PasswordHistory, p.LockoutThreshold, p.PasswordComplexity, p.MaxPasswordAgeDays),
		"The domain password policy permits weak passwords or lacks lockout. This materially increases the success probability of a password-spray campaign.",
		strings.Join(reasons, "; "),
		"Set Default Domain Policy: minPwdLength=14, pwdProperties=1 (complexity), lockoutThreshold=10, lockoutDuration=15, lockoutObservationWindow=15, maxPwdAge=60. Consider fine-grained password policies (PSO) for service accounts.",
	)}
}

func parseIntAttr(attrs map[string][]string, name string, def int) int {
	v, ok := attrs[name]
	if !ok || len(v) == 0 {
		return def
	}
	n := 0
	for _, c := range v[0] {
		if c < '0' || c > '9' {
			return def
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func hasAttr(attrs map[string][]string, name, want string) bool {
	v, ok := attrs[name]
	if !ok || len(v) == 0 {
		return false
	}
	for _, s := range v {
		if s == want {
			return true
		}
	}
	return false
}
