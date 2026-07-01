package auth

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

// SPNService is a single Service Principal Name entry as returned by LDAP
// queries against the AD directory.
type SPNService struct {
	Account         string
	SPN             string
	PasswordLastSet string
	Enabled         bool
	AdminCount      bool // true → likely a privileged account
}

// EnumerateSPNs queries an AD domain for accounts with non-empty servicePrincipalName.
// It expects an LDAPTester-like object that can search the directory; we keep
// the LDAP dependency out of this file by accepting a callback.
//
// The reason for the callback shape: the LDAP search results are 100+ attributes
// per entry, and we want to map them into our minimal SPNService type without
// pulling LDAP-specific types into this package.
type LDAPSearchFn func(filter string, attrs []string) ([]map[string][]string, error)

// EnumerateSPNs returns every account with at least one SPN.
func EnumerateSPNs(search LDAPSearchFn) ([]SPNService, error) {
	if search == nil {
		return nil, fmt.Errorf("nil LDAP search callback")
	}
	entries, err := search(
		"(servicePrincipalName=*)",
		[]string{"sAMAccountName", "servicePrincipalName", "pwdLastSet", "userAccountControl", "adminCount"},
	)
	if err != nil {
		return nil, err
	}
	out := []SPNService{}
	for _, e := range entries {
		spns := e["servicePrincipalName"]
		if len(spns) == 0 {
			continue
		}
		account := firstOrEmpty(e["sAMAccountName"])
		uac := parseUAC(firstOrEmpty(e["userAccountControl"]))
		out = append(out, SPNService{
			Account:         account,
			SPN:             spns[0],
			PasswordLastSet: firstOrEmpty(e["pwdLastSet"]),
			Enabled:         uac&0x2 == 0, // UF_ACCOUNTDISABLE = 0x2
			AdminCount:      len(e["adminCount"]) > 0 && strings.EqualFold(firstOrEmpty(e["adminCount"]), "TRUE"),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Account < out[j].Account
	})
	return out, nil
}

// KerberoastTarget is a per-account recommendation: which account to attack
// first, with what etype, and the rough difficulty.
type KerberoastTarget struct {
	Account         string
	SPN             string
	RC4Vulnerable   bool   // true when the account supports RC4-HMAC
	Difficulty      string // "low"|"medium"|"high"
	PasswordAgeDays int
	Notes           string
}

// KerberoastTargetList is the alias used for the (slice) receiver pattern.
type KerberoastTargetList []KerberoastTarget

// KerberoastTargets ranks SPN-having accounts by crackability. Accounts
// with old passwords, low admin count, and enabled are prime targets.
//
// We don't actually request the TGS here — that step requires a TGT. The
// caller (apophis_kerberoast MCP tool) supplies one. This function just
// produces the priority list and the rationale.
func RankKerberoastTargets(services []SPNService) KerberoastTargetList {
	out := []KerberoastTarget{}
	now := nowEpochDays()
	for _, s := range services {
		if !s.Enabled {
			continue
		}
		age := now - parsePwdLastSetDays(s.PasswordLastSet)
		diff := "medium"
		notes := ""
		switch {
		case age > 365:
			diff = "low"
			notes = "password > 1y old"
		case s.AdminCount:
			diff = "high"
			notes = "privileged (adminCount=1)"
		case age > 180:
			diff = "low"
			notes = "password > 180d old"
		}
		out = append(out, KerberoastTarget{
			Account:         s.Account,
			SPN:             s.SPN,
			RC4Vulnerable:   true, // we always request RC4; if the KDC agrees, the TGS is crackable
			Difficulty:      diff,
			PasswordAgeDays: age,
			Notes:           notes,
		})
	}
	// Sort by difficulty (low first), then by account name.
	rank := map[string]int{"low": 0, "medium": 1, "high": 2}
	list := KerberoastTargetList(out)
	sort.Slice(list, func(i, j int) bool {
		if rank[list[i].Difficulty] != rank[list[j].Difficulty] {
			return rank[list[i].Difficulty] < rank[list[j].Difficulty]
		}
		return list[i].Account < list[j].Account
	})
	return list
}

// ToFindings renders a kerberoast target list as report findings.
func (t KerberoastTargetList) ToFindings(target string) []models.Finding {
	findings := []models.Finding{}
	if len(t) == 0 {
		return findings
	}
	low := 0
	accts := []string{}
	for _, k := range t {
		accts = append(accts, k.Account)
		if k.Difficulty == "low" {
			low++
		}
	}
	if low > 0 {
		findings = append(findings, F(
			VectorKerberoast,
			fmt.Sprintf("Kerberoastable service accounts on %s (%d low-difficulty)", target, low),
			target,
			models.SeverityHigh,
			fmt.Sprintf("low_difficulty=%d total=%d", low, len(t)),
			"One or more accounts have SPNs and passwords old enough to crack with a small wordlist. With a TGT, requesting the TGS and cracking offline is silent — no failed logins, no account lockout.",
			"GetUserSPNs.py -request -dc-ip <DC> <REALM>/<USER>:<PASS> -hashes :NTHASH  # crack with hashcat -m 13100",
			"Use a 25+ character random password for service accounts (managed service accounts / gMSA). Rotate regularly. Set 'msDS-SupportedEncryptionTypes' to AES-only so RC4 TGS-REQ is rejected.",
		))
	}
	if len(t) > 0 {
		findings = append(findings, F(
			VectorKerberoast,
			fmt.Sprintf("Kerberoast target inventory on %s (%d accounts)", target, len(t)),
			target,
			models.SeverityInfo,
			fmt.Sprintf("accounts=%v", accts),
			"Inventory of all SPN-holding, enabled accounts. Use this list with the kerberoast MCP tool (apophis_kerberoast) to retrieve TGS tickets and crack offline.",
			"apophis_kerberoast with target=DC and the credential of any domain user.",
			"Migrate service accounts to gMSAs (Group Managed Service Accounts) which rotate passwords automatically.",
		))
	}
	return findings
}

// --- helpers --------------------------------------------------------------

func firstOrEmpty(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func parseUAC(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// pwdLastSet is a Windows FILETIME (100-ns since 1601-01-01). We only
// return the day-difference to today, which is enough for prioritisation.
func parsePwdLastSetDays(s string) int {
	if s == "" {
		return 0
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	const ticksPerDay = 10000000 * 86400
	const epochDays1601To1970 = 134774
	days := n / ticksPerDay
	return days - epochDays1601To1970
}

func nowEpochDays() int {
	return int(time.Now().Unix() / 86400)
}
