package models

import "time"

type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

func (s Severity) Score() int {
	switch s {
	case SeverityCritical:
		return 10
	case SeverityHigh:
		return 7
	case SeverityMedium:
		return 4
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 0
	}
	return 0
}

type Strategy string

const (
	StrategyRecon      Strategy = "recon"
	StrategyAggressive Strategy = "aggressive"
	StrategyStealth    Strategy = "stealth"
	StrategyWebFocus   Strategy = "web-focus"
	StrategyNetFocus   Strategy = "network-focus"
	StrategyAuthFocus  Strategy = "auth-focus"
	StrategyAI         Strategy = "ai-planned"
)

// TargetProfile describes the inferred shape of a target. The planner uses
// this to pick the right mix of strategies for the next audit.
type TargetProfile struct {
	Host           string   `json:"host"`
	HasWeb         bool     `json:"has_web"`
	HasHTTPS       bool     `json:"has_https"`
	OpenPorts      []int    `json:"open_ports"`
	ServiceBanners []string `json:"service_banners"`
	WAF            string   `json:"waf,omitempty"`
	Cloud          string   `json:"cloud,omitempty"`
	PublicFacing   bool     `json:"public_facing"`
}

type Target struct {
	Host    string
	Ports   []int
	URL     string
	Timeout time.Duration
	// StealthOpts is honored by the port scanner and web probes.
	StealthOpts StealthOptions
	// AIPlanner is the name of an AI-driven planner to use instead of the
	// fixed strategy pool (empty = use the orchestrator's default).
	AIPlanner string
}

// StealthOptions controls evasive scanning behavior. When Stealth=true the
// scanners throttle their rate, add jitter, and avoid the obvious payload
// patterns. Decoys are a list of IPs/hostnames to issue benign noise requests
// to so logs are diluted.
type StealthOptions struct {
	Stealth      bool     `json:"stealth,omitempty"`
	RatePerSec   int      `json:"rate_per_sec,omitempty"` // 0 = use sensible default per strategy
	JitterMs     int      `json:"jitter_ms,omitempty"`    // max random delay added per probe
	RandomizeUA  bool     `json:"randomize_ua,omitempty"`
	Decoys       []string `json:"decoys,omitempty"`
	EvasionMode  string   `json:"evasion_mode,omitempty"` // "off"|"low"|"medium"|"high"
	MaxRetries   int      `json:"max_retries,omitempty"`
	AdaptiveRate bool     `json:"adaptive_rate,omitempty"`
}

type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp|udp
	State    string `json:"state"`
	Service  string `json:"service"`
	Banner   string `json:"banner"`
	Version  string `json:"version"`
}

type HTTPInfo struct {
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	Title          string            `json:"title"`
	Server         string            `json:"server"`
	PoweredBy      string            `json:"powered_by"`
	Headers        map[string]string `json:"headers"`
	ResponseTimeMs int64             `json:"response_time_ms"`
	TLS            *TLSInfo          `json:"tls,omitempty"`
	WAF            *WAFInfo          `json:"waf,omitempty"`
}

type TLSInfo struct {
	Version    string   `json:"version"`
	Cipher     string   `json:"cipher"`
	Expires    string   `json:"expires"`
	SelfSigned bool     `json:"self_signed"`
	Issues     []string `json:"issues"`
}

// WAFInfo describes the WAF/CDN observed in front of the target. Vendor is
// the lowercase vendor name (cloudflare, aws, akamai, imperva, f5, sucuri,
// modsecurity, etc.) and Evidence is the response header / cookie / behaviour
// that triggered the detection.
type WAFInfo struct {
	Vendor   string   `json:"vendor"`
	Evidence []string `json:"evidence"`
	Blocked  bool     `json:"blocked"`
}

// ExploitRef is a pointer to an exploit that targets a CVE. It can come
// from the local PoC store, Exploit-DB, the Metasploit module DB, or a
// GitHub advisory.
type ExploitRef struct {
	Source string `json:"source"` // poc|exploitdb|metasploit|ghsa
	ID     string `json:"id"`     // PoC id, EDB-####, module path, GHSA id
	URL    string `json:"url,omitempty"`
	Title  string `json:"title,omitempty"`
	Risk   string `json:"risk,omitempty"`
}

type Finding struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Severity    Severity          `json:"severity"`
	Category    string            `json:"category"`
	Target      string            `json:"target"`
	Port        int               `json:"port,omitempty"`
	Evidence    string            `json:"evidence"`
	Description string            `json:"description"`
	Exploit     string            `json:"exploit"`
	Remediation string            `json:"remediation"`
	References  []string          `json:"references"`
	CVE         []string          `json:"cve,omitempty"`
	CVSS        float64           `json:"cvss,omitempty"`
	Strategy    Strategy          `json:"strategy"`
	WorkerID    string            `json:"worker_id"`
	DetectedAt  time.Time         `json:"detected_at"`
	Tags        []string          `json:"tags,omitempty"`
	ThreatIntel map[string]any    `json:"threat_intel,omitempty"`
	ExploitRefs []ExploitRef      `json:"exploit_refs,omitempty"`
	Extra       map[string]string `json:"extra,omitempty"`
}

type Report struct {
	Target        Target     `json:"target"`
	GeneratedAt   time.Time  `json:"generated_at"`
	Duration      string     `json:"duration"`
	Workers       int        `json:"workers"`
	TotalChecks   int        `json:"total_checks"`
	Findings      []Finding  `json:"findings"`
	Summary       Summary    `json:"summary"`
	PortScan      []PortInfo `json:"port_scan"`
	HTTPDiscovery []HTTPInfo `json:"http_discovery"`
	WAF           *WAFInfo   `json:"waf,omitempty"`
	ThreatIntel   TIReport   `json:"threat_intel"`
	PlanTrace     []string   `json:"plan_trace,omitempty"`
}

type Summary struct {
	Total     int `json:"total"`
	Critical  int `json:"critical"`
	High      int `json:"high"`
	Medium    int `json:"medium"`
	Low       int `json:"low"`
	Info      int `json:"info"`
	RiskScore int `json:"risk_score"`
}

// TIReport aggregates threat-intelligence observations gathered during the
// audit. Sources is the list of intel providers that contributed, Hits is the
// per-provider verdict for the target IP/host.
type TIReport struct {
	Sources []string          `json:"sources,omitempty"`
	Hits    map[string]string `json:"hits,omitempty"`
}
