// Package planner picks the strategy mix to use for the next audit given a
// target profile. The default planner is rule-based and requires no LLM;
// the rule table is intentionally simple and well-justified so the auditor
// can explain why a strategy was chosen.
//
// If the user wants an LLM-driven planner, they can call apophis_plan
// explicitly and supply their own list of strategies; this package never
// makes outbound LLM calls itself.
package planner

import (
	"fmt"
	"sort"
	"strings"

	"github.com/apophis-eng/apophis/internal/models"
)

// Plan is the result of a planning pass.
type Plan struct {
	Strategies []models.Strategy `json:"strategies"`
	Rationale  []string          `json:"rationale"`
}

// Planner is the strategy selection interface.
type Planner interface {
	Plan(p models.TargetProfile) Plan
}

// RuleBased is the default planner. It picks strategies based on the
// inferred shape of the target: web presence, public-facing vs internal,
// the open ports and the service banners, and any detected WAF.
type RuleBased struct{}

func NewRuleBased() *RuleBased { return &RuleBased{} }

// Plan returns 4-6 strategies appropriate for the profile.
func (r *RuleBased) Plan(p models.TargetProfile) Plan {
	picks := []models.Strategy{}
	rationale := []string{}

	// Always-on baseline.
	picks = append(picks, models.StrategyRecon)
	rationale = append(rationale, "recon is always included as the discovery baseline")

	// Public-facing web target → web focus.
	if p.HasWeb {
		picks = append(picks, models.StrategyWebFocus)
		rationale = append(rationale, fmt.Sprintf("HTTP service present on %s", p.Host))
	}
	// Web with WAF → stealth variant — too aggressive = burned immediately.
	if p.WAF != "" {
		picks = append(picks, models.StrategyStealth)
		rationale = append(rationale, fmt.Sprintf("WAF detected (%s) — stealth scanning recommended to avoid alerting defenders", p.WAF))
	}
	// Internal / private IP with auth-bait services → auth focus.
	if !p.PublicFacing {
		picks = append(picks, models.StrategyAuthFocus)
		rationale = append(rationale, "target appears internal — default-cred probing is in scope")
	}
	// Many ports open → network focus.
	if len(p.OpenPorts) >= 5 {
		picks = append(picks, models.StrategyNetFocus)
		rationale = append(rationale, fmt.Sprintf("%d open ports observed — network enumeration pays off", len(p.OpenPorts)))
	}
	// Service banners indicate specific protocols → targeted strategies.
	if hasAny(p.ServiceBanners, []string{"smb", "msrpc", "netbios"}) {
		picks = append(picks, models.StrategyAggressive)
		rationale = append(rationale, "SMB/MSRPC service detected — aggressive SMB enumeration")
	}
	if hasAny(p.ServiceBanners, []string{"ssh", "telnet"}) {
		picks = append(picks, models.StrategyAuthFocus)
		rationale = append(rationale, "SSH/Telnet present — credential brute-force in scope")
	}
	if hasAny(p.ServiceBanners, []string{"ldap", "ldaps"}) {
		picks = append(picks, models.StrategyAuthFocus)
		rationale = append(rationale, "LDAP present — AD/LDAP recon")
	}
	if hasAny(p.ServiceBanners, []string{"snmp", "udp-snmp"}) {
		picks = append(picks, models.StrategyAggressive)
		rationale = append(rationale, "SNMP present — community string brute")
	}
	if hasAny(p.ServiceBanners, []string{"rdp", "vnc"}) {
		picks = append(picks, models.StrategyAuthFocus)
		rationale = append(rationale, "RDP/VNC — credential brute-force and BlueKeep-style checks")
	}

	// Deduplicate and cap at 6.
	uniq := uniqStrategies(picks)
	if len(uniq) > 6 {
		uniq = uniq[:6]
	}
	return Plan{Strategies: uniq, Rationale: rationale}
}

// ProfileFromReport derives a TargetProfile from the report of a previous
// recon pass. This is what the planner consumes in practice: the orchestrator
// runs a fast recon, builds a profile, and feeds it to the planner.
func ProfileFromReport(r *models.Report) models.TargetProfile {
	p := models.TargetProfile{Host: r.Target.Host}
	for _, port := range r.PortScan {
		p.OpenPorts = append(p.OpenPorts, port.Port)
		if port.Service != "" {
			p.ServiceBanners = append(p.ServiceBanners, port.Service)
		}
		if port.Banner != "" {
			p.ServiceBanners = append(p.ServiceBanners, port.Banner)
		}
	}
	for _, h := range r.HTTPDiscovery {
		if h.StatusCode > 0 {
			p.HasWeb = true
		}
		if h.URL != "" && strings.HasPrefix(h.URL, "https://") {
			p.HasHTTPS = true
		}
		if h.WAF != nil && h.WAF.Vendor != "" {
			p.WAF = h.WAF.Vendor
		}
	}
	if r.WAF != nil {
		p.WAF = r.WAF.Vendor
	}
	sort.Ints(p.OpenPorts)
	return p
}

func uniqStrategies(in []models.Strategy) []models.Strategy {
	seen := map[models.Strategy]bool{}
	out := []models.Strategy{}
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func hasAny(haystack, needles []string) bool {
	low := strings.ToLower(strings.Join(haystack, " "))
	for _, n := range needles {
		if strings.Contains(low, strings.ToLower(n)) {
			return true
		}
	}
	return false
}
