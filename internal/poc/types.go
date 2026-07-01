package poc

import "time"

type PoCType string

const (
	PoCTypeShell  PoCType = "shell"
	PoCTypePython PoCType = "python"
	PoCTypeRuby   PoCType = "ruby"
	PoCTypeJS     PoCType = "js"
	PoCTypeBinary PoCType = "binary"
	PoCTypeNuclei PoCType = "nuclei"
	PoCTypeMsf    PoCType = "msf"
	PoCTypeCurl   PoCType = "curl"
	PoCTypeOther  PoCType = "other"
)

func (t PoCType) Valid() bool {
	switch t {
	case PoCTypeShell, PoCTypePython, PoCTypeRuby, PoCTypeJS,
		PoCTypeBinary, PoCTypeNuclei, PoCTypeMsf, PoCTypeCurl, PoCTypeOther:
		return true
	}
	return false
}

func (t PoCType) Runtime() string {
	switch t {
	case PoCTypeShell:
		return "sh"
	case PoCTypePython:
		return "python3"
	case PoCTypeRuby:
		return "ruby"
	case PoCTypeJS:
		return "node"
	case PoCTypeCurl:
		return "curl"
	}
	return ""
}

type RiskLevel int

const (
	RiskInfo        RiskLevel = 0
	RiskSafe        RiskLevel = 1
	RiskRCE         RiskLevel = 2
	RiskDestructive RiskLevel = 3
)

func (r RiskLevel) String() string {
	switch r {
	case RiskInfo:
		return "info"
	case RiskSafe:
		return "safe"
	case RiskRCE:
		return "rce"
	case RiskDestructive:
		return "destructive"
	}
	return "unknown"
}

func ParseRisk(s string) RiskLevel {
	switch s {
	case "info":
		return RiskInfo
	case "safe":
		return RiskSafe
	case "rce":
		return RiskRCE
	case "destructive":
		return RiskDestructive
	}
	return -1
}

type SandboxLevel string

const (
	SandboxL1 SandboxLevel = "L1"
	SandboxL2 SandboxLevel = "L2"
	SandboxL3 SandboxLevel = "L3"
)

func (s SandboxLevel) Valid() bool {
	switch s {
	case SandboxL1, SandboxL2, SandboxL3:
		return true
	}
	return false
}

type PoC struct {
	ID          string    `json:"id"`
	Source      string    `json:"source"`
	CVE         string    `json:"cve"`
	Title       string    `json:"title"`
	Author      string    `json:"author"`
	Type        PoCType   `json:"type"`
	Path        string    `json:"path"`
	Raw         string    `json:"raw"`
	Args        []string  `json:"args"`
	Env         []string  `json:"env"`
	Risk        RiskLevel `json:"risk"`
	RequiresNet bool      `json:"requires_net"`
	Signature   string    `json:"signature"`
	CreatedAt   time.Time `json:"created_at"`
}

type ExecConfig struct {
	Enabled          bool
	MaxRisk          RiskLevel
	AllowContainer   bool
	AllowMicroVM     bool
	ExecutorUser     string
	ExecutionTimeout time.Duration
	AllowlistPath    string
	NoAllowlist      bool
	DryRun           bool
	AuditDir         string
	SecretKeyPath    string
	MaxSandboxLevel  SandboxLevel
	WorkDir          string

	MSFRPCURL  string
	MSFRPCUser string
	MSFRPCPass string

	NucleiBinary       string
	NucleiTemplatesDir string

	BoofuzzPython  string
	BoofuzzWorkDir string
}

func (c ExecConfig) MaxSandbox() SandboxLevel {
	if c.MaxSandboxLevel == "" {
		return SandboxL1
	}
	return c.MaxSandboxLevel
}

type RunRequest struct {
	PoC          *PoC
	Target       string
	SandboxLevel SandboxLevel
	TimeoutSec   int
	Confirm      bool
	ExtraArgs    []string
	ExtraEnv     []string
	UserNote     string
}

type RunResult struct {
	ExecutionID     string       `json:"execution_id"`
	StartedAt       time.Time    `json:"started_at"`
	FinishedAt      time.Time    `json:"finished_at"`
	DurationMs      int64        `json:"duration_ms"`
	ExitCode        int          `json:"exit_code"`
	Signal          string       `json:"signal"`
	Stdout          string       `json:"stdout"`
	Stderr          string       `json:"stderr"`
	Sandboxed       bool         `json:"sandboxed"`
	SandboxLevel    SandboxLevel `json:"sandbox_level"`
	SandboxInfo     AuditSandbox `json:"sandbox_info"`
	ExploitVerified bool         `json:"exploit_verified"`
	VulnConfirmed   bool         `json:"vuln_confirmed"`
	Error           string       `json:"error,omitempty"`
	DryRun          bool         `json:"dry_run"`
}

type AuditPoC struct {
	ID        string `json:"id"`
	CVE       string `json:"cve"`
	Type      string `json:"type"`
	Signature string `json:"signature"`
	Risk      string `json:"risk"`
	Source    string `json:"source"`
}

type AuditSandbox struct {
	Level      string           `json:"level"`
	Namespaces []string         `json:"namespaces,omitempty"`
	Rlimits    map[string]int64 `json:"rlimits"`
	Seccomp    string           `json:"seccomp"`
	Workdir    string           `json:"workdir"`
}

type AuditRecord struct {
	ID              string       `json:"id"`
	StartedAt       time.Time    `json:"started_at"`
	FinishedAt      time.Time    `json:"finished_at"`
	DurationMs      int64        `json:"duration_ms"`
	PoC             AuditPoC     `json:"poc"`
	Target          string       `json:"target"`
	Sandbox         AuditSandbox `json:"sandbox"`
	Cmd             []string     `json:"cmd"`
	Env             []string     `json:"env"`
	ExitCode        int          `json:"exit_code"`
	Signal          string       `json:"signal"`
	Stdout          string       `json:"stdout"`
	Stderr          string       `json:"stderr"`
	ExploitVerified bool         `json:"exploit_verified"`
	VulnConfirmed   bool         `json:"vuln_confirmed"`
	UserConfirmedAt *time.Time   `json:"user_confirmed_at,omitempty"`
	UserNote        string       `json:"user_note,omitempty"`
	DryRun          bool         `json:"dry_run"`
	HMAC            string       `json:"hmac"`
}
