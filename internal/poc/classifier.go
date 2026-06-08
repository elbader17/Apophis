package poc

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

type classifierRule struct {
	keyword string
	risk    RiskLevel
}

var classifierRules = []classifierRule{
	// destructive
	{"rm -rf", RiskDestructive},
	{"mkfs", RiskDestructive},
	{"dd if=", RiskDestructive},
	{":(){:|:&};:", RiskDestructive},
	{"fork bomb", RiskDestructive},
	{"drop table", RiskDestructive},
	{"shutdown", RiskDestructive},
	{"reboot", RiskDestructive},
	{"halt", RiskDestructive},
	{"poweroff", RiskDestructive},
	{"cryptominer", RiskDestructive},
	{"xmrig", RiskDestructive},
	{"curl | sh", RiskDestructive},
	{"curl|sh", RiskDestructive},
	{"wget | sh", RiskDestructive},
	{"|bash", RiskDestructive},
	{"| sh", RiskDestructive},

	// rce
	{"exec", RiskRCE},
	{"subprocess", RiskRCE},
	{"os.system", RiskRCE},
	{"system(", RiskRCE},
	{"popen", RiskRCE},
	{"/bin/sh", RiskRCE},
	{"/bin/bash", RiskRCE},
	{"cmd.exe", RiskRCE},
	{"pwntools", RiskRCE},
	{"msfconsole", RiskRCE},
	{"metasploit", RiskRCE},
	{"exploit/multi", RiskRCE},
	{"reverse_shell", RiskRCE},
	{"bind_shell", RiskRCE},
	{"shellcraft", RiskRCE},
	{"payload.run", RiskRCE},
	{"eval(", RiskRCE},
	{"process.mainModule", RiskRCE},
	{"child_process", RiskRCE},

	// safe (network-touching)
	{"connect", RiskSafe},
	{"socket", RiskSafe},
	{"http", RiskSafe},
	{"https", RiskSafe},
	{"requests.", RiskSafe},
	{"urllib", RiskSafe},
	{"http.client", RiskSafe},
	{"fetch(", RiskSafe},
	{"axios", RiskSafe},
	{"curl ", RiskSafe},
	{"wget ", RiskSafe},
	{"nc ", RiskSafe},
	{"ncat", RiskSafe},
	{"telnet", RiskSafe},
	{"ssh ", RiskSafe},
	{"ftp ", RiskSafe},
}

// Classifier infers a risk level for a PoC from its raw source code.
type Classifier struct {
	extra []classifierRule
}

func NewClassifier() *Classifier {
	return &Classifier{}
}

func (c *Classifier) WithRule(keyword string, r RiskLevel) *Classifier {
	c.extra = append(c.extra, classifierRule{keyword: strings.ToLower(keyword), risk: r})
	return c
}

func (c *Classifier) Classify(raw string, ptype PoCType, requiresNet bool) RiskLevel {
	low := strings.ToLower(raw)
	rules := append([]classifierRule{}, classifierRules...)
	rules = append(rules, c.extra...)

	sort.SliceStable(rules, func(i, j int) bool { return rules[i].risk > rules[j].risk })

	highest := RiskInfo
	for _, r := range rules {
		if strings.Contains(low, r.keyword) {
			if r.risk > highest {
				highest = r.risk
			}
		}
	}
	if highest == RiskInfo && requiresNet {
		highest = RiskSafe
	}
	if highest == RiskInfo && (ptype == PoCTypeShell || ptype == PoCTypePython || ptype == PoCTypeRuby) {
		highest = RiskSafe
	}
	return highest
}

func (c *Classifier) Reason(raw string) []string {
	low := strings.ToLower(raw)
	seen := map[string]bool{}
	matches := []string{}
	for _, r := range classifierRules {
		if strings.Contains(low, r.keyword) && !seen[r.keyword] {
			seen[r.keyword] = true
			matches = append(matches, r.keyword)
		}
	}
	sort.Strings(matches)
	return matches
}

func Signature(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return "sha256:" + hex.EncodeToString(sum[:])
}
