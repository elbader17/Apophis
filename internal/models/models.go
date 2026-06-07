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
)

type Target struct {
	Host    string
	Ports   []int
	URL     string
	Timeout time.Duration
}

type PortInfo struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
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
}

type TLSInfo struct {
	Version    string   `json:"version"`
	Cipher     string   `json:"cipher"`
	Expires    string   `json:"expires"`
	SelfSigned bool     `json:"self_signed"`
	Issues     []string `json:"issues"`
}

type Finding struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    Severity  `json:"severity"`
	Category    string    `json:"category"`
	Target      string    `json:"target"`
	Port        int       `json:"port,omitempty"`
	Evidence    string    `json:"evidence"`
	Description string    `json:"description"`
	Exploit     string    `json:"exploit"`
	Remediation string    `json:"remediation"`
	References  []string  `json:"references"`
	CVE         []string  `json:"cve,omitempty"`
	CVSS        float64   `json:"cvss,omitempty"`
	Strategy    Strategy  `json:"strategy"`
	WorkerID    string    `json:"worker_id"`
	DetectedAt  time.Time `json:"detected_at"`
}

type Report struct {
	Target       Target     `json:"target"`
	GeneratedAt  time.Time  `json:"generated_at"`
	Duration     string     `json:"duration"`
	Workers      int        `json:"workers"`
	TotalChecks  int        `json:"total_checks"`
	Findings     []Finding  `json:"findings"`
	Summary      Summary    `json:"summary"`
	PortScan     []PortInfo `json:"port_scan"`
	HTTPDiscovery []HTTPInfo `json:"http_discovery"`
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
