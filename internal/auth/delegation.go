package auth

import (
	"fmt"
	"sort"
	"strings"

	"github.com/apophis-eng/apophis/internal/models"
)

// DelegationType identifies the flavour of Kerberos delegation we found.
type DelegationType string

const (
	DelUnconstrained DelegationType = "unconstrained"
	DelConstrained   DelegationType = "constrained"
	DelRBCD          DelegationType = "rbcd"
	DelAny           DelegationType = "any-auth" // TRUSTED_TO_AUTH_FOR_DELEGATION (Protocol Transition)
)

// DelegationTarget is the per-account delegation finding.
type DelegationTarget struct {
	Account string
	Type    DelegationType
	Targets []string // msDS-AllowedToDelegateTo (constrained / RBCD)
	IsDC    bool     // true when the account is a Domain Controller
	Notes   string
}

// EnumerateDelegation walks a list of LDAP attributes and reports every
// account that has one of the delegation-relevant UAC bits set or the
// msDS-AllowedToDelegateTo / msDS-AllowedToActOnBehalfOfOtherIdentity
// attributes populated.
//
// uacBits is a map of sAMAccountName → userAccountControl value (as int).
// attrs is a map of sAMAccountName → map of attribute name → []string.
//
// We expect the caller to have already pulled the directory-wide set; this
// keeps the function pure (no I/O) and trivially testable.
func EnumerateDelegation(uac map[string]int, attrs map[string]map[string][]string) []DelegationTarget {
	out := []DelegationTarget{}
	// First pass: UAC bits.
	for acct, bits := range uac {
		// TRUSTED_FOR_DELEGATION (unconstrained) = 0x80000
		if bits&0x80000 != 0 {
			out = append(out, DelegationTarget{
				Account: acct,
				Type:    DelUnconstrained,
				IsDC:    strings.HasSuffix(acct, "$"),
				Notes:   "TRUSTED_FOR_DELEGATION UAC bit set",
			})
		}
		// TRUSTED_TO_AUTH_FOR_DELEGATION (S4U2Self / protocol transition) = 0x1000000
		if bits&0x1000000 != 0 {
			out = append(out, DelegationTarget{
				Account: acct,
				Type:    DelAny,
				IsDC:    strings.HasSuffix(acct, "$"),
				Notes:   "TRUSTED_TO_AUTH_FOR_DELEGATION UAC bit set (protocol transition)",
			})
		}
	}
	// Second pass: msDS-AllowedToDelegateTo (constrained delegation).
	for acct, a := range attrs {
		if tgts, ok := a["msDS-AllowedToDelegateTo"]; ok && len(tgts) > 0 {
			out = append(out, DelegationTarget{
				Account: acct,
				Type:    DelConstrained,
				Targets: append([]string{}, tgts...),
				IsDC:    strings.HasSuffix(acct, "$"),
				Notes:   "msDS-AllowedToDelegateTo populated",
			})
		}
		// msDS-AllowedToActOnBehalfOfOtherIdentity (RBCD) — stored as a
		// security descriptor. We flag it when the attribute is present
		// and non-empty; parsing the SDDL is out of scope for the audit.
		if raw, ok := a["msDS-AllowedToActOnBehalfOfOtherIdentity"]; ok && len(raw) > 0 && len(raw[0]) > 0 {
			out = append(out, DelegationTarget{
				Account: acct,
				Type:    DelRBCD,
				Targets: []string{"<set in ACL>"},
				IsDC:    strings.HasSuffix(acct, "$"),
				Notes:   "msDS-AllowedToActOnBehalfOfOtherIdentity populated",
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return string(out[i].Type) < string(out[j].Type)
		}
		return out[i].Account < out[j].Account
	})
	return out
}

// ToFindings emits one finding per delegation type with all the affected
// accounts listed in Evidence.
func DelegationToFindings(target string, d []DelegationTarget) []models.Finding {
	findings := []models.Finding{}
	if len(d) == 0 {
		return findings
	}
	byType := map[DelegationType][]DelegationTarget{}
	for _, dt := range d {
		byType[dt.Type] = append(byType[dt.Type], dt)
	}
	if accts := byType[DelUnconstrained]; len(accts) > 0 {
		names := acctsToStrings(accts)
		hasDC := false
		for _, a := range accts {
			if a.IsDC {
				hasDC = true
			}
		}
		sev := models.SeverityHigh
		desc := "Accounts with TRUSTED_FOR_DELEGATION set can impersonate any user against any service in the domain. An attacker that compromises such an account (or any machine that has it) can extract the TGT of a Domain Admin by inducing a DC auth (PrinterBug / PetitPotam / DFSCoerce)."
		if hasDC {
			sev = models.SeverityCritical
			desc = "Domain Controllers have TRUSTED_FOR_DELEGATION set — this is required for the KDC itself, but it means a compromised DC allows unconstrained impersonation of any principal in the forest."
		}
		findings = append(findings, F(
			VectorDelegationUncon,
			fmt.Sprintf("Unconstrained delegation on %s (%d accounts)", target, len(accts)),
			target,
			sev,
			fmt.Sprintf("accounts=%v", names),
			desc,
			"Monitor for 4769 events with '0x80000' (unconstrained) ticket option. Use PrinterBug / PetitPotam to coerce a DC auth, then monitor for a 4624 with Logon Process = 'Negotiate' and SeImpersonatePrivilege. Extract TGTs with Rubeus / mimikatz.",
			"Remove TRUSTED_FOR_DELEGATION from every non-DC account. For DCs, monitor 4769 closely. Consider enabling 'Account is sensitive and cannot be delegated' for Tier-0 accounts.",
		))
	}
	if accts := byType[DelRBCD]; len(accts) > 0 {
		findings = append(findings, F(
			VectorDelegationRBCD,
			fmt.Sprintf("Resource-Based Constrained Delegation (RBCD) on %s (%d accounts)", target, len(accts)),
			target,
			models.SeverityHigh,
			fmt.Sprintf("accounts=%v", acctsToStrings(accts)),
			"Accounts with msDS-AllowedToActOnBehalfOfOtherIdentity allow the listed principals to impersonate any domain user against this account via S4U2Self + S4U2Proxy. RBCD is the modern delegation abuse path: combine with GenericAll / GenericWrite / WriteDACL on the target to gain code execution as any user.",
			"Get-DomainObjectAcl -Identity <target> | ?{$_.ActiveDirectoryRights -match 'GenericAll|GenericWrite|WriteDacl|WriteProperty'}. Use rbcd.py or Impacket's rbcd.py to add a controlled account to msDS-AllowedToActOnBehalfOfOtherIdentity, then s4u2self+proxy for the TGS.",
			"Audit and minimise RBCD grants. Tier-0 services (DCs, AD CS, ADFS) should not have RBCD set unless absolutely required. Use 'Get-DomainObject -Properties msDS-AllowedToActOnBehalfOfOtherIdentity' to enumerate.",
		))
	}
	if accts := byType[DelConstrained]; len(accts) > 0 {
		findings = append(findings, F(
			VectorDelegationConstr,
			fmt.Sprintf("Constrained delegation on %s (%d accounts)", target, len(accts)),
			target,
			models.SeverityMedium,
			fmt.Sprintf("accounts=%v", acctsToStrings(accts)),
			"Accounts with msDS-AllowedToDelegateTo set can impersonate any user against the listed services. Combined with S4U2Self (when TRUSTED_TO_AUTH_FOR_DELEGATION is also set) the attacker can reach any user → any service pair without ever owning the target's password.",
			"getST.py -spn <SPN> -impersonate Administrator -dc-ip <DC> '<REALM>/<controlled_acct>:<pass>'",
			"Restrict msDS-AllowedToDelegateTo to a small set of services. Where possible, prefer RBCD (where the resource owner controls the grant) over constrained delegation.",
		))
	}
	return findings
}

func acctsToStrings(in []DelegationTarget) []string {
	out := make([]string, 0, len(in))
	for _, a := range in {
		out = append(out, a.Account)
	}
	return out
}
