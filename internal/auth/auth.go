// Package auth implements authentication-layer attack primitives against
// Active Directory (Kerberos + NTLM + LDAP) and other identity systems.
//
// All operations are passive / semi-passive and emit findings rather than
// performing destructive actions:
//
//   - AS-REP roasting detection (no credentials required)
//   - SPN enumeration + Kerberoasting scaffolding (requires creds / TGT)
//   - Delegation abuse detection (unconstrained / constrained / RBCD)
//   - NTLMv1 / LM downgrade detection
//   - Password policy + lockout threshold probing
//   - Targeted password-spray wordlist generation
//
// Run only against systems you own or have explicit written authorization
// to test. The package never sends a single packet on its own — every probe
// is invoked explicitly by the caller.
package auth

import (
	"github.com/apophis-eng/apophis/internal/models"
)

// AttackVector is the category tag attached to authentication findings. It
// maps cleanly to MITRE ATT&CK and is also the value used in Finding.Tags.
type AttackVector string

const (
	VectorASREPRoast         AttackVector = "as-rep-roasting"
	VectorKerberoast         AttackVector = "kerberoasting"
	VectorDelegationUncon    AttackVector = "unconstrained-delegation"
	VectorDelegationRBCD     AttackVector = "rbcd"
	VectorDelegationConstr   AttackVector = "constrained-delegation"
	VectorNTLMv1             AttackVector = "ntlmv1"
	VectorWeakPasswordPolicy AttackVector = "weak-password-policy"
	VectorSpray              AttackVector = "password-spray"
)

// F wraps models.Finding with a strongly-typed attack vector so callers
// don't have to fish through Tags / Category.
func F(vector AttackVector, title, target string, sev models.Severity, evidence, desc, exploit, remediation string) models.Finding {
	return models.Finding{
		Title:       title,
		Severity:    sev,
		Category:    "AuthAttack",
		Target:      target,
		Evidence:    evidence,
		Description: desc,
		Exploit:     exploit,
		Remediation: remediation,
		Tags:        []string{"auth-attack", string(vector)},
	}
}

// MergeFinding copies non-zero fields from extra into base.
func MergeFinding(base models.Finding, extra models.Finding) models.Finding {
	if extra.Title != "" {
		base.Title = extra.Title
	}
	if extra.Description != "" {
		base.Description = extra.Description
	}
	if extra.Evidence != "" {
		base.Evidence = extra.Evidence
	}
	if extra.Severity != "" {
		base.Severity = extra.Severity
	}
	if extra.Remediation != "" {
		base.Remediation = extra.Remediation
	}
	if len(extra.References) > 0 {
		base.References = append(base.References, extra.References...)
	}
	return base
}
