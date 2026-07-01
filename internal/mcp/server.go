package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	adauth "github.com/apophis-eng/apophis/internal/auth"
	"github.com/apophis-eng/apophis/internal/credleak"
	"github.com/apophis-eng/apophis/internal/logger"
	"github.com/apophis-eng/apophis/internal/models"
	"github.com/apophis-eng/apophis/internal/orchestrator"
	"github.com/apophis-eng/apophis/internal/planner"
	"github.com/apophis-eng/apophis/internal/poc"
	"github.com/apophis-eng/apophis/internal/research"
	"github.com/apophis-eng/apophis/internal/stealth"
	"github.com/apophis-eng/apophis/internal/store"
	"github.com/apophis-eng/apophis/internal/threatintel"
	"github.com/apophis-eng/apophis/internal/tokens"
	"github.com/apophis-eng/apophis/internal/tools/cve"
	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
	"github.com/apophis-eng/apophis/internal/tools/cve/embeddings"
	"github.com/apophis-eng/apophis/internal/tools/cve/exploitlink"
	"github.com/apophis-eng/apophis/internal/tools/ftp"
	"github.com/apophis-eng/apophis/internal/tools/ldap"
	"github.com/apophis-eng/apophis/internal/tools/network"
	"github.com/apophis-eng/apophis/internal/tools/nuclei"
	"github.com/apophis-eng/apophis/internal/tools/smb"
	"github.com/apophis-eng/apophis/internal/tools/snmp"
	"github.com/apophis-eng/apophis/internal/tools/ssl"
	"github.com/apophis-eng/apophis/internal/tools/web"
	"github.com/apophis-eng/apophis/internal/webauth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const serverName = "apophis"
const serverVersion = "0.3.0"

type Server struct {
	store       *store.Store
	dynamic     *dynamic.Store
	agent       *research.Agent
	defaultW    int
	defaultTO   time.Duration
	lastReport  string
	exec        *poc.State
	tiProviders []threatintel.Provider
	embeddings  *embeddings.Index
	exploits    *exploitlink.Linker
	nucleiDir   string
	planner     planner.Planner
}

type AuditInput struct {
	Target   string `json:"target" jsonschema:"hostname or IP to audit"`
	URL      string `json:"url,omitempty" jsonschema:"optional base URL"`
	Workers  int    `json:"workers,omitempty" jsonschema:"number of parallel agents (1-16)"`
	Timeout  string `json:"timeout,omitempty" jsonschema:"per-probe timeout like '5s'"`
	Ports    string `json:"ports,omitempty" jsonschema:"comma-separated ports, blank for top common"`
	Strategy string `json:"strategy,omitempty" jsonschema:"force a single strategy for all workers (recon,aggressive,stealth,web-focus,net-focus,auth-focus,ai-planned)"`
	Stealth  bool   `json:"stealth,omitempty" jsonschema:"enable stealth mode (rate limit + jitter)"`
	Rate     int    `json:"rate,omitempty" jsonschema:"probes per second (overrides default per strategy)"`
	Jitter   int    `json:"jitter_ms,omitempty" jsonschema:"max random jitter per probe in ms"`
	Decoys   string `json:"decoys,omitempty" jsonschema:"comma-separated decoy hosts to issue noise to"`
	Evasion  string `json:"evasion,omitempty" jsonschema:"off|low|medium|high evasion profile"`
}

type PortScanInput struct {
	Target  string `json:"target" jsonschema:"hostname or IP to scan"`
	Ports   string `json:"ports,omitempty" jsonschema:"comma-separated ports (tcp)"`
	UDP     bool   `json:"udp,omitempty" jsonschema:"also scan UDP"`
	Timeout string `json:"timeout,omitempty" jsonschema:"per-probe timeout"`
}

type UDPScanInput struct {
	Target  string `json:"target" jsonschema:"hostname or IP to scan"`
	Ports   string `json:"ports,omitempty" jsonschema:"comma-separated ports (udp). Blank = common UDP set"`
	Timeout string `json:"timeout,omitempty" jsonschema:"per-probe timeout"`
}

type DeepProtoInput struct {
	Target  string `json:"target" jsonschema:"hostname or IP to probe"`
	Timeout string `json:"timeout,omitempty" jsonschema:"per-probe timeout"`
}

type WebAuditInput struct {
	URL     string `json:"url" jsonschema:"URL to audit (http or https)"`
	Timeout string `json:"timeout,omitempty" jsonschema:"per-probe timeout"`
	Deep    bool   `json:"deep,omitempty" jsonschema:"run aggressive web checks (LFI, SQLi, XSS)"`
}

type CheckCVEInput struct {
	Service string `json:"service" jsonschema:"service identifier (ssh, http, smb, rdp, log4j, etc)"`
	Version string `json:"version" jsonschema:"version string"`
	Banner  string `json:"banner,omitempty" jsonschema:"optional raw banner"`
}

type SimilarCVEInput struct {
	Query string `json:"query" jsonschema:"free-text description of the issue to look up"`
	K     int    `json:"k,omitempty" jsonschema:"top-k results (default 5)"`
}

type ThreatIntelInput struct {
	Target string `json:"target" jsonschema:"IP or hostname to look up"`
}

type WAFDetectInput struct {
	URL     string `json:"url" jsonschema:"URL to probe"`
	Timeout string `json:"timeout,omitempty" jsonschema:"per-probe timeout"`
}

type ListReportsInput struct {
	Target string `json:"target,omitempty" jsonschema:"filter by target substring"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max results (default 20)"`
}

type GetReportInput struct {
	ID     string `json:"id" jsonschema:"report id returned by audit_target"`
	Format string `json:"format,omitempty" jsonschema:"json|summary|findings (default: summary)"`
}

type DeleteReportInput struct {
	ID string `json:"id" jsonschema:"report id"`
}

type ExploitInput struct {
	ID         string `json:"id,omitempty" jsonschema:"report id containing the finding"`
	Title      string `json:"title,omitempty" jsonschema:"finding title to look up"`
	Category   string `json:"category,omitempty" jsonschema:"finding category filter"`
	Severity   string `json:"severity,omitempty" jsonschema:"minimum severity filter (CRITICAL,HIGH,MEDIUM,LOW,INFO)"`
	MaxResults int    `json:"max_results,omitempty" jsonschema:"max number of exploit guides to return (default 5)"`
}

type RegisterInput struct{}

type ResearchInput struct {
	Sources       []string `json:"sources,omitempty" jsonschema:"which sources to sync (nvd,cisa-kev,osv,exploitdb,ghsa,securityweek,thehackernews,packetstorm). Empty = all"`
	DaysBack      int      `json:"days_back,omitempty" jsonschema:"fetch entries modified in the last N days (default 7)"`
	MaxPerSource  int      `json:"max_per_source,omitempty" jsonschema:"max entries per source (default 50)"`
	GenerateStubs bool     `json:"generate_stubs,omitempty" jsonschema:"write Go check stubs to internal/tools/cve/generated/"`
}

type SearchCVEInput struct {
	Keyword  string  `json:"keyword,omitempty" jsonschema:"search keyword (CVE id, vendor, product, title)"`
	MinCVSS  float64 `json:"min_cvss,omitempty" jsonschema:"minimum CVSS score (e.g. 7.0)"`
	Severity string  `json:"severity,omitempty" jsonschema:"exact severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)"`
	OnlyKEV  bool    `json:"only_kev,omitempty" jsonschema:"only CISA KEV (known-exploited) entries"`
	Limit    int     `json:"limit,omitempty" jsonschema:"max results (default 25)"`
}

type RecentCVEInput struct {
	Days    int     `json:"days,omitempty" jsonschema:"only show CVEs from the last N days (default 30)"`
	MinCVSS float64 `json:"min_cvss,omitempty" jsonschema:"minimum CVSS score (default 0)"`
	Limit   int     `json:"limit,omitempty" jsonschema:"max results (default 25)"`
	OnlyKEV bool    `json:"only_kev,omitempty" jsonschema:"only CISA KEV entries"`
}

type GenerateStubInput struct {
	CVE string `json:"cve" jsonschema:"CVE id to generate a Go check stub for"`
}

type PoCListInput struct {
	CVE     string `json:"cve,omitempty" jsonschema:"filter by CVE id"`
	Source  string `json:"source,omitempty" jsonschema:"filter by source (exploitdb,ghsa,...)"`
	MinRisk string `json:"min_risk,omitempty" jsonschema:"minimum risk (info,safe,rce,destructive)"`
	MaxRisk string `json:"max_risk,omitempty" jsonschema:"maximum risk (info,safe,rce,destructive)"`
	Limit   int    `json:"limit,omitempty" jsonschema:"max results (default 25)"`
}

type PoCRunInput struct {
	PoCID        string   `json:"poc_id" jsonschema:"PoC id from apophis_poc_list"`
	Target       string   `json:"target" jsonschema:"hostname or IP to attack (must be in allowlist)"`
	SandboxLevel string   `json:"sandbox_level,omitempty" jsonschema:"L1 (default), L2 (container) or L3 (microVM)"`
	TimeoutSec   int      `json:"timeout_sec,omitempty" jsonschema:"max execution time in seconds"`
	Confirm      bool     `json:"confirm" jsonschema:"MUST be the literal boolean true to run"`
	ExtraArgs    []string `json:"extra_args,omitempty" jsonschema:"additional CLI args, validated against PoC allowlist"`
	UserNote     string   `json:"user_note,omitempty" jsonschema:"optional human-readable note for the audit log"`
}

type PoCKillInput struct {
	ExecutionID string `json:"execution_id" jsonschema:"id returned by apophis_poc_run"`
}

type PoCHistoryInput struct {
	Target string `json:"target,omitempty" jsonschema:"filter by target"`
	Since  string `json:"since,omitempty" jsonschema:"RFC3339 timestamp; only return executions after"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max results (default 50)"`
}

type PoCAllowlistInput struct {
	Action string `json:"action" jsonschema:"add | list | remove"`
	Target string `json:"target,omitempty" jsonschema:"target to add/remove (IP, CIDR, or hostname)"`
	Note   string `json:"note,omitempty" jsonschema:"optional human-readable note"`
}

// --- Auth / token attack inputs -------------------------------------------

type ASREPInput struct {
	DC      string   `json:"dc" jsonschema:"KDC IP address (the Domain Controller)"`
	Realm   string   `json:"realm" jsonschema:"Kerberos realm (uppercase AD DNS domain, e.g. CORP.LOCAL)"`
	Users   []string `json:"users" jsonschema:"list of samAccountNames to probe (use apophis_ldap_audit to enumerate first)"`
	Timeout string   `json:"timeout,omitempty" jsonschema:"per-probe timeout"`
}

type KerberoastInput struct {
	DC          string `json:"dc" jsonschema:"KDC IP address"`
	Realm       string `json:"realm" jsonschema:"Kerberos realm"`
	LDAPBase    string `json:"ldap_base,omitempty" jsonschema:"optional LDAP base DN to scope the SPN search"`
	Credentials string `json:"credentials,omitempty" jsonschema:"optional 'user:password' or 'DOMAIN\\user:password' for AS-REQ preauth"`
}

type DelegationInput struct {
	UAC   map[string]int                 `json:"uac" jsonschema:"map of sAMAccountName → userAccountControl bits (decimal)"`
	Attrs map[string]map[string][]string `json:"attrs" jsonschema:"map of sAMAccountName → attribute name → values (msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfIdentity)"`
}

type NTLMInput struct {
	Target  string `json:"target" jsonschema:"hostname or IP of the target"`
	URL     string `json:"url,omitempty" jsonschema:"optional HTTP URL to probe for NTLMSSP challenge"`
	Timeout string `json:"timeout,omitempty" jsonschema:"per-probe timeout"`
}

type PasswordPolicyInput struct {
	Attrs map[string][]string `json:"attrs" jsonschema:"LDAP attributes for the Default Domain Policy object (minPwdLength, pwdHistoryLength, maxPwdAge, lockoutThreshold, lockoutDuration, lockoutObservationWindow, pwdProperties)"`
}

type SprayInput struct {
	Company  string   `json:"company" jsonschema:"company name (used to seed the wordlist)"`
	Domain   string   `json:"domain,omitempty" jsonschema:"primary DNS domain (split on '.' for company seed)"`
	Years    []int    `json:"years,omitempty" jsonschema:"years to append (default: current year ±1)"`
	Include  []string `json:"include,omitempty" jsonschema:"extra words to include"`
	MaxWords int      `json:"max_words,omitempty" jsonschema:"max word count (default 200)"`
}

type JWTInput struct {
	Token  string `json:"token" jsonschema:"JWT to inspect (Bearer header is optional)"`
	Source string `json:"source,omitempty" jsonschema:"human-friendly source label (cookie|page|header)"`
}

type JWTBruteInput struct {
	Token string `json:"token" jsonschema:"JWT to brute-force (must be HS256/HS384/HS512)"`
}

type SAMLInput struct {
	Response string `json:"response" jsonschema:"base64-encoded SAML Response (or raw XML)"`
	Source   string `json:"source,omitempty" jsonschema:"human-friendly source label"`
}

type OAuthInput struct {
	AuthEndpoint     string   `json:"auth_endpoint" jsonschema:"OAuth/OIDC authorize URL"`
	RedirectURI      string   `json:"redirect_uri" jsonschema:"the SP's redirect_uri"`
	AllowedRedirects []string `json:"allowed_redirects,omitempty" jsonschema:"list of redirect URIs the IdP would accept"`
	ClientID         string   `json:"client_id,omitempty" jsonschema:"OAuth client_id"`
	Scopes           []string `json:"scopes,omitempty" jsonschema:"requested scopes"`
}

type AuthAuditInput struct {
	URL                string `json:"url" jsonschema:"URL of the login / auth page to audit"`
	CSRFParam          string `json:"csrf_param,omitempty" jsonschema:"expected CSRF parameter name (e.g. 'csrf_token')"`
	ResetHostTemplate  string `json:"reset_host_template,omitempty" jsonschema:"password-reset URL template (look for {HOST} / <host> tokens)"`
	MFAFingerprintJSON string `json:"mfa_fingerprint_json,omitempty" jsonschema:"optional MFAFingerprint JSON ({\"has_mfa\":false,\"params\":[\"otp\"]})"`
}

type CredLeakInput struct {
	URL string `json:"url" jsonschema:"base URL to probe for credential leaks"`
}

type ServerOpts struct {
	Store       *store.Store
	Dynamic     *dynamic.Store
	Agent       *research.Agent
	ExecState   *poc.State
	DefaultWork int
	DefaultTO   time.Duration
	NucleiDir   string
	TIKeys      ThreatIntelKeys
}

type ThreatIntelKeys struct {
	GreyNoise  string
	Shodan     string
	AbuseIPDB  string
	VirusTotal string
}

func NewServer(opts ServerOpts) *Server {
	emb := embeddings.New()
	emb.Rebuild(opts.Dynamic.All())
	provs := threatintel.New(threatintel.ProviderConfig{
		GreyNoiseKey:  opts.TIKeys.GreyNoise,
		ShodanKey:     opts.TIKeys.Shodan,
		AbuseIPDBKey:  opts.TIKeys.AbuseIPDB,
		VirusTotalKey: opts.TIKeys.VirusTotal,
	})
	linker := &exploitlink.Linker{
		Metasploit: exploitlink.MetasploitModules(),
	}
	if opts.ExecState != nil && opts.ExecState.Store != nil {
		linker.PoC = opts.ExecState.Store
	}
	return &Server{
		store:       opts.Store,
		dynamic:     opts.Dynamic,
		agent:       opts.Agent,
		defaultW:    opts.DefaultWork,
		defaultTO:   opts.DefaultTO,
		exec:        opts.ExecState,
		tiProviders: provs,
		embeddings:  emb,
		exploits:    linker,
		nucleiDir:   opts.NucleiDir,
		planner:     planner.NewRuleBased(),
	}
}

// NewServer is preserved as the legacy entry point used by older call sites
// (tests). It delegates to NewServer with zero TI keys and no PoC store.
func NewServerLegacy(s *store.Store, dyn *dynamic.Store, agent *research.Agent, execState *poc.State, defaultWorkers int, defaultTimeout time.Duration) *Server {
	return NewServer(ServerOpts{
		Store: s, Dynamic: dyn, Agent: agent, ExecState: execState,
		DefaultWork: defaultWorkers, DefaultTO: defaultTimeout,
	})
}

// ensure backward-compat for older call sites
func init() { _ = NewServerLegacy }

func (s *Server) Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_audit", Description: "Run a full multi-strategy parallel vulnerability audit against a target. Optionally stealthy, AI-planned, with WAF detection and threat-intel enrichment. Returns a report id and a summary."}, s.handleAudit)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_portscan", Description: "Quick TCP port scan with banner grabbing."}, s.handlePortScan)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_udp_scan", Description: "Quick UDP scan with protocol-specific probes (DNS, NTP, SNMP, NetBIOS-NS, TFTP, SIP). State is open|filtered when no ICMP is received."}, s.handleUDPScan)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_smb_audit", Description: "Deep SMB check: detects SMBv1 (EternalBlue pre-condition), signing enforcement, null-session, share enumeration, OS disclosure."}, s.handleSMBAudit)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_ldap_audit", Description: "Deep LDAP/LDAPS check: anonymous bind, cleartext LDAP, rootDSE fingerprint (AD / OpenLDAP / 389 DS), naming context leak, signing/sealing."}, s.handleLDAPAudit)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_snmp_audit", Description: "SNMPv2c community-string brute against UDP/161 (public, private, manager, monitor, etc). Returns sysDescr/sysName on hit."}, s.handleSNMPAudit)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_ftp_audit", Description: "FTP check: anonymous login, weak credentials, STARTTLS advertised, SYST disclosure."}, s.handleFTPAudit)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_waf_detect", Description: "Detect the WAF / CDN in front of a URL by sending a baseline and a malicious probe and matching response fingerprints (Cloudflare, Akamai, AWS, Imperva, F5, Sucuri, ModSecurity, etc)."}, s.handleWAFDetect)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_threatintel", Description: "Look up the target IP/host in GreyNoise Community, Shodan InternetDB (free), AbuseIPDB, and VirusTotal. Verdict is folded into the next audit report."}, s.handleThreatIntel)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_web_audit", Description: "Focused web application audit. Checks security headers, exposed paths, common web vulns (LFI/SQLi/XSS if deep=true), and TLS."}, s.handleWebAudit)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_check_cve", Description: "Match a service+version+banner against the local CVE database (static + dynamic). Returns any known critical CVEs (EternalBlue, BlueKeep, Log4Shell, Heartbleed, ProxyLogon, Zerologon, etc) with linked exploits."}, s.handleCheckCVE)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_similar_cve", Description: "Search the CVE database by free-text description using a TF-IDF vector index. Returns the top-k most similar CVEs to the query."}, s.handleSimilarCVE)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_list_reports", Description: "List all stored vulnerability reports."}, s.handleListReports)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_get_report", Description: "Retrieve a stored report."}, s.handleGetReport)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_delete_report", Description: "Delete a report."}, s.handleDeleteReport)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_recommend_exploitation", Description: "Look up exploitation guidance for findings, filtered by report id, title, category or minimum severity."}, s.handleExploit)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_status", Description: "Show Apophis server status: version, store path, default settings, last report id, threat-intel provider list, planner info."}, s.handleStatus)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_research", Description: "Sync the latest CVEs from public vulnerability databases."}, s.handleResearch)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_search_cve", Description: "Search the dynamic CVE database by keyword / CVSS / severity / KEV-only."}, s.handleSearchCVE)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_recent_cves", Description: "Show the most recent CVEs from the dynamic database."}, s.handleRecentCVE)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_generate_stub", Description: "Generate a Go check stub for a given CVE."}, s.handleGenerateStub)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_poc_list", Description: "List PoCs in the local store."}, s.handlePoCList)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_poc_preview", Description: "Preview what apophis_poc_run would do WITHOUT executing."}, s.handlePoCPreview)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_poc_run", Description: "Execute a PoC against a target. Requires confirm:true."}, s.handlePoCRun)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_poc_history", Description: "List past PoC executions."}, s.handlePoCHistory)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_poc_kill", Description: "Kill a running PoC execution."}, s.handlePoCKill)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_poc_allowlist", Description: "Manage the allow-list of permitted targets."}, s.handlePoCAllowlist)

	// --- Auth / token attack tools ---------------------------------------
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_asrep_roast", Description: "Probe a list of AD accounts for DONT_REQUIRE_PREAUTH (AS-REP-roastable). Unauthenticated; sends AS-REQ and inspects the response. RC4-HMAC accounts are crackable offline."}, s.handleASREPRoast)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_kerberoast", Description: "Inventory SPN-holding service accounts in the directory, ranked by crackability (password age, admin count, RC4 etype)."}, s.handleKerberoast)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_delegation_audit", Description: "Detect accounts vulnerable to unconstrained / constrained / RBCD Kerberos delegation abuse from supplied LDAP attributes."}, s.handleDelegationAudit)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_ntlm_dialects", Description: "Probe a target for weak NTLMSSP dialect negotiation (LM, OEM-only, no NTLM, no signing, no 128-bit keys). SMB and HTTP endpoints."}, s.handleNTLMDialects)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_password_policy", Description: "Score the AD password policy (length, lockout, complexity) from LDAP attributes."}, s.handlePasswordPolicy)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_spray", Description: "Generate a targeted password-spray wordlist seeded with company name, year and seasons."}, s.handleSpray)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_jwt_attack", Description: "Inspect a JWT for alg=none, RS↔HS confusion, kid traversal, JWK injection, exp in the past."}, s.handleJWTAttack)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_jwt_brute", Description: "Brute-force the HMAC secret of an HS256/384/512 JWT against the bundled top-1000 weak-secret list."}, s.handleJWTBrute)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_saml_attack", Description: "Inspect a SAML Response for XSW (multiple assertions), comment injection, missing NotOnOrAfter, weak signature algorithm, missing NameID."}, s.handleSAMLAttack)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_oauth_audit", Description: "Audit an OAuth / OIDC config for open-redirect, missing state, weak state entropy, wildcard redirect_uri, origin drift."}, s.handleOAuthAudit)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_auth_audit", Description: "Run the web-auth flow audit (cookie flags, CSRF token, password-reset Host-header, rate-limit detection) against a URL."}, s.handleAuthAudit)
	mcp.AddTool(server, &mcp.Tool{Name: "apophis_cred_leak", Description: "Run credential-leak probes (entropy / hardcoded / backup files / .git) against a URL."}, s.handleCredLeak)
}

func (s *Server) handleAudit(ctx context.Context, req *mcp.CallToolRequest, in AuditInput) (*mcp.CallToolResult, any, error) {
	if in.Target == "" {
		return errorResult("target is required"), nil, nil
	}
	workers := in.Workers
	if workers <= 0 {
		workers = s.defaultW
	}
	if workers > 16 {
		workers = 16
	}
	to := s.defaultTO
	if in.Timeout != "" {
		if d, err := time.ParseDuration(in.Timeout); err == nil {
			to = d
		}
	}

	t := models.Target{
		Host:    in.Target,
		URL:     in.URL,
		Timeout: to,
	}
	if in.Ports != "" {
		t.Ports = parsePorts(in.Ports)
	}
	if in.Stealth || in.Rate > 0 || in.Jitter > 0 || in.Decoys != "" || in.Evasion != "" {
		t.StealthOpts = models.StealthOptions{
			Stealth:      in.Stealth,
			RatePerSec:   in.Rate,
			JitterMs:     in.Jitter,
			EvasionMode:  in.Evasion,
			AdaptiveRate: true,
		}
		if in.Decoys != "" {
			for _, d := range strings.Split(in.Decoys, ",") {
				d = strings.TrimSpace(d)
				if d != "" {
					t.StealthOpts.Decoys = append(t.StealthOpts.Decoys, d)
				}
			}
		}
	}

	logger.Info("apophis_audit", fmt.Sprintf("target=%s workers=%d timeout=%s stealth=%v strategy=%s", t.Host, workers, to, in.Stealth, in.Strategy))

	orch := orchestrator.New(t, workers)
	orch.NucleiDir = s.nucleiDir
	orch.Exploits = s.exploits
	orch.ThreatIntel = s.tiProviders
	if in.Strategy != "" {
		if err := orch.ForceStrategy(models.Strategy(in.Strategy)); err != nil {
			return errorResult(err.Error()), nil, nil
		}
	}

	r, err := orch.Run(ctx)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}

	id, err := s.store.Save(r)
	if err != nil {
		return errorResult("save failed: " + err.Error()), nil, nil
	}
	s.lastReport = id

	out := auditOutput{
		ReportID:      id,
		Target:        t.Host,
		URL:           r.Target.URL,
		Duration:      r.Duration,
		Workers:       r.Workers,
		RiskScore:     r.Summary.RiskScore,
		Total:         r.Summary.Total,
		BySeverity:    bySev(r.Summary),
		TopFindings:   topFindings(r.Findings, 5),
		OpenPorts:     len(r.PortScan),
		HTTPDiscovery: len(r.HTTPDiscovery),
		ThreatIntel:   r.ThreatIntel,
		Next:          "use apophis_get_report with id=" + id + " (format=findings) for full list, or apophis_recommend_exploitation to see exploit commands",
	}
	return jsonResult(out)
}

type auditOutput struct {
	ReportID      string          `json:"report_id"`
	Target        string          `json:"target"`
	URL           string          `json:"url"`
	Duration      string          `json:"duration"`
	Workers       int             `json:"workers"`
	RiskScore     int             `json:"risk_score"`
	Total         int             `json:"total"`
	BySeverity    map[string]int  `json:"by_severity"`
	TopFindings   []findingBrief  `json:"top_findings"`
	OpenPorts     int             `json:"open_ports"`
	HTTPDiscovery int             `json:"http_discovery"`
	ThreatIntel   models.TIReport `json:"threat_intel"`
	Next          string          `json:"next_steps"`
}

type findingBrief struct {
	Title    string `json:"title"`
	Severity string `json:"severity"`
	Category string `json:"category"`
	Target   string `json:"target"`
	Exploit  string `json:"exploit"`
	CVE      string `json:"cve,omitempty"`
}

func (s *Server) handlePortScan(ctx context.Context, req *mcp.CallToolRequest, in PortScanInput) (*mcp.CallToolResult, any, error) {
	if in.Target == "" {
		return errorResult("target is required"), nil, nil
	}
	to := s.defaultTO
	if in.Timeout != "" {
		if d, err := time.ParseDuration(in.Timeout); err == nil {
			to = d
		}
	}
	ps := network.NewPortScanner(to)
	ports := parsePorts(in.Ports)
	if len(ports) == 0 {
		ports = network.CommonPortsList()
	}
	tcpResults := ps.Scan(ctx, in.Target, ports)
	var udpResults []models.PortInfo
	if in.UDP {
		udpResults = network.NewUDPScanner(to).Scan(ctx, in.Target, nil)
	}
	sort.Slice(tcpResults, func(i, j int) bool { return tcpResults[i].Port < tcpResults[j].Port })
	return jsonResult(map[string]any{
		"target":   in.Target,
		"scanned":  len(ports),
		"open_tcp": len(tcpResults),
		"open_udp": len(udpResults),
		"tcp":      tcpResults,
		"udp":      udpResults,
	})
}

func (s *Server) handleUDPScan(ctx context.Context, req *mcp.CallToolRequest, in UDPScanInput) (*mcp.CallToolResult, any, error) {
	if in.Target == "" {
		return errorResult("target is required"), nil, nil
	}
	to := s.defaultTO
	if in.Timeout != "" {
		if d, err := time.ParseDuration(in.Timeout); err == nil {
			to = d
		}
	}
	us := network.NewUDPScanner(to)
	if in.Ports == "" {
		results := us.Scan(ctx, in.Target, nil)
		return jsonResult(map[string]any{
			"target":   in.Target,
			"scanned":  len(network.CommonUDPPorts()),
			"open_any": len(results),
			"udp":      results,
		})
	}
	results := us.Scan(ctx, in.Target, parsePorts(in.Ports))
	return jsonResult(map[string]any{
		"target":  in.Target,
		"scanned": len(parsePorts(in.Ports)),
		"open":    len(results),
		"udp":     results,
	})
}

func (s *Server) handleSMBAudit(ctx context.Context, req *mcp.CallToolRequest, in DeepProtoInput) (*mcp.CallToolResult, any, error) {
	if in.Target == "" {
		return errorResult("target is required"), nil, nil
	}
	to := s.defaultTO
	if in.Timeout != "" {
		if d, err := time.ParseDuration(in.Timeout); err == nil {
			to = d
		}
	}
	tester := smb.New(to)
	// First do a quick TCP probe to find open port 445 / 139. Use a fake
	// PortInfo slice so the tester uses its built-in picker.
	d := net_dialer(to)
	ports := smbProbePorts(ctx, d, in.Target)
	findings, info := tester.Audit(ctx, in.Target, ports)
	return jsonResult(map[string]any{
		"target":   in.Target,
		"info":     info,
		"findings": findings,
		"count":    len(findings),
		"tip":      "use apophis_recommend_exploitation with category=SMB to see metasploit modules",
	})
}

func (s *Server) handleLDAPAudit(ctx context.Context, req *mcp.CallToolRequest, in DeepProtoInput) (*mcp.CallToolResult, any, error) {
	if in.Target == "" {
		return errorResult("target is required"), nil, nil
	}
	to := s.defaultTO
	if in.Timeout != "" {
		if d, err := time.ParseDuration(in.Timeout); err == nil {
			to = d
		}
	}
	tester := ldap.New(to)
	d := net_dialer(to)
	ports := ldapProbePorts(ctx, d, in.Target)
	findings, info := tester.Audit(ctx, in.Target, ports)
	return jsonResult(map[string]any{
		"target":   in.Target,
		"info":     info,
		"findings": findings,
		"count":    len(findings),
	})
}

func (s *Server) handleSNMPAudit(ctx context.Context, req *mcp.CallToolRequest, in DeepProtoInput) (*mcp.CallToolResult, any, error) {
	if in.Target == "" {
		return errorResult("target is required"), nil, nil
	}
	to := s.defaultTO
	if in.Timeout != "" {
		if d, err := time.ParseDuration(in.Timeout); err == nil {
			to = d
		}
	}
	tester := snmp.New(to)
	d := net_dialer(to)
	ports := snmpProbePorts(ctx, d, in.Target)
	findings, info := tester.Audit(ctx, in.Target, ports)
	return jsonResult(map[string]any{
		"target":   in.Target,
		"info":     info,
		"findings": findings,
		"count":    len(findings),
	})
}

func (s *Server) handleFTPAudit(ctx context.Context, req *mcp.CallToolRequest, in DeepProtoInput) (*mcp.CallToolResult, any, error) {
	if in.Target == "" {
		return errorResult("target is required"), nil, nil
	}
	to := s.defaultTO
	if in.Timeout != "" {
		if d, err := time.ParseDuration(in.Timeout); err == nil {
			to = d
		}
	}
	tester := ftp.New(to)
	d := net_dialer(to)
	ports := ftpProbePorts(ctx, d, in.Target)
	findings, info := tester.Audit(ctx, in.Target, ports)
	return jsonResult(map[string]any{
		"target":   in.Target,
		"info":     info,
		"findings": findings,
		"count":    len(findings),
	})
}

func (s *Server) handleWAFDetect(ctx context.Context, req *mcp.CallToolRequest, in WAFDetectInput) (*mcp.CallToolResult, any, error) {
	if in.URL == "" {
		return errorResult("url is required"), nil, nil
	}
	to := s.defaultTO
	if in.Timeout != "" {
		if d, err := time.ParseDuration(in.Timeout); err == nil {
			to = d
		}
	}
	d := stealth.NewWAFDetector(to)
	info := d.Detect(ctx, in.URL)
	if info == nil {
		return jsonResult(map[string]any{"url": in.URL, "waf": nil, "tip": "no WAF signatures matched — target appears unprotected"})
	}
	return jsonResult(map[string]any{"url": in.URL, "waf": info, "next": "consider re-running apophis_audit with stealth=true to avoid alerting the WAF"})
}

func (s *Server) handleThreatIntel(ctx context.Context, req *mcp.CallToolRequest, in ThreatIntelInput) (*mcp.CallToolResult, any, error) {
	if in.Target == "" {
		return errorResult("target is required"), nil, nil
	}
	if len(s.tiProviders) == 0 {
		return errorResult("no threat-intel providers configured — set APOPHIS_GREYNOISE_KEY / APOPHIS_SHODAN_KEY / APOPHIS_ABUSEIPDB_KEY / APOPHIS_VIRUSTOTAL_KEY"), nil, nil
	}
	verdicts := threatintel.LookupAll(ctx, s.tiProviders, in.Target)
	return jsonResult(map[string]any{"target": in.Target, "verdicts": verdicts})
}

func (s *Server) handleWebAudit(ctx context.Context, req *mcp.CallToolRequest, in WebAuditInput) (*mcp.CallToolResult, any, error) {
	if in.URL == "" {
		return errorResult("url is required"), nil, nil
	}
	to := s.defaultTO
	if in.Timeout != "" {
		if d, err := time.ParseDuration(in.Timeout); err == nil {
			to = d
		}
	}
	ws := web.NewWebScanner(to)

	info, err := ws.Fetch(ctx, in.URL)
	if err != nil {
		return errorResult("fetch failed: " + err.Error()), nil, nil
	}

	findings := []models.Finding{}
	headerIssues := ws.CheckSecurityHeaders(info.Headers)
	for _, h := range headerIssues {
		findings = append(findings, models.Finding{
			Title:       h,
			Severity:    sevFromHeader(h),
			Category:    "Web",
			Target:      in.URL,
			Evidence:    h,
			Description: h,
			Exploit:     "Manual inspection recommended.",
			Remediation: "Configure the missing security header on the web server.",
		})
	}
	if in.Deep {
		for _, e := range ws.CheckDirectoryTraversal(ctx, in.URL) {
			findings = append(findings, models.Finding{Title: "LFI/Dir-Trav", Severity: models.SeverityCritical, Category: "Web", Target: in.URL, Evidence: e, Description: e, Exploit: "Use ../../../etc/passwd and chained payloads.", Remediation: "Sanitize path input."})
		}
		for _, e := range ws.CheckSQLInjection(ctx, in.URL) {
			findings = append(findings, models.Finding{Title: "SQLi", Severity: models.SeverityCritical, Category: "Web", Target: in.URL, Evidence: e, Description: e, Exploit: "Use sqlmap -u URL --batch", Remediation: "Use parameterized queries."})
		}
		for _, e := range ws.CheckXSS(ctx, in.URL) {
			findings = append(findings, models.Finding{Title: "Reflected XSS", Severity: models.SeverityHigh, Category: "Web", Target: in.URL, Evidence: e, Description: e, Exploit: "Craft URL with payload, victim executes JS.", Remediation: "Output encode + CSP."})
		}
	}
	disco := web.NewDiscovery(ws.Client())
	findings = append(findings, disco.BrutePaths(ctx, in.URL)...)

	// Nuclei run if templates are loaded.
	loader := nuclei.NewLoader(s.nucleiDir)
	templates, _ := loader.Load()
	for _, raw := range nuclei.BundledTemplates {
		t, err := nuclei.Parse(raw)
		if err == nil {
			templates = append(templates, t)
		}
	}
	if len(templates) > 0 {
		runner := nuclei.NewRunner(8 * time.Second)
		for _, t := range templates {
			findings = append(findings, runner.Run(ctx, t, in.URL)...)
		}
	}

	return jsonResult(map[string]any{
		"url":        in.URL,
		"status":     info.StatusCode,
		"server":     info.Server,
		"title":      info.Title,
		"headers":    info.Headers,
		"tls":        info.TLS,
		"findings":   findings,
		"findings_n": len(findings),
	})
}

func (s *Server) handleCheckCVE(ctx context.Context, req *mcp.CallToolRequest, in CheckCVEInput) (*mcp.CallToolResult, any, error) {
	if in.Service == "" {
		return errorResult("service is required"), nil, nil
	}
	m := cve.New().WithDynamic(s.dynamic)
	findings := m.Match(in.Service, in.Version, in.Banner)
	for i := range findings {
		if s.exploits != nil && len(findings[i].CVE) > 0 {
			refs := s.exploits.Refs(findings[i].CVE)
			if len(refs) > 0 {
				findings[i].ExploitRefs = refs
				findings[i].Exploit += "\nLinked exploits: " + s.exploits.Summary(refs)
			}
		}
	}
	return jsonResult(map[string]any{
		"service":    in.Service,
		"version":    in.Version,
		"matched":    len(findings),
		"findings":   findings,
		"db_static":  14,
		"db_dynamic": s.dynamic.Len(),
		"db_indexed": s.embeddings.Len(),
	})
}

func (s *Server) handleSimilarCVE(ctx context.Context, req *mcp.CallToolRequest, in SimilarCVEInput) (*mcp.CallToolResult, any, error) {
	if in.Query == "" {
		return errorResult("query is required"), nil, nil
	}
	if s.embeddings.Len() == 0 {
		return errorResult("embeddings index is empty — run apophis_research first"), nil, nil
	}
	k := in.K
	if k <= 0 {
		k = 5
	}
	results := s.embeddings.Search(in.Query, k)
	return jsonResult(map[string]any{
		"query":   in.Query,
		"k":       k,
		"count":   len(results),
		"results": results,
	})
}

func (s *Server) handleListReports(ctx context.Context, req *mcp.CallToolRequest, in ListReportsInput) (*mcp.CallToolResult, any, error) {
	limit := in.Limit
	if limit <= 0 {
		limit = 20
	}
	list := s.store.List(in.Target)
	if len(list) > limit {
		list = list[:limit]
	}
	return jsonResult(map[string]any{
		"count":   len(list),
		"reports": list,
	})
}

func (s *Server) handleGetReport(ctx context.Context, req *mcp.CallToolRequest, in GetReportInput) (*mcp.CallToolResult, any, error) {
	if in.ID == "" {
		return errorResult("id is required"), nil, nil
	}
	r, err := s.store.Get(in.ID)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}
	format := in.Format
	if format == "" {
		format = "summary"
	}
	switch format {
	case "json":
		return jsonResult(r)
	case "findings":
		return jsonResult(map[string]any{
			"report_id":      in.ID,
			"target":         r.Target.Host,
			"generated_at":   r.GeneratedAt,
			"summary":        r.Summary,
			"port_scan":      r.PortScan,
			"http_discovery": r.HTTPDiscovery,
			"findings":       r.Findings,
			"threat_intel":   r.ThreatIntel,
			"waf":            r.WAF,
		})
	default:
		return jsonResult(map[string]any{
			"report_id":      in.ID,
			"target":         r.Target.Host,
			"url":            r.Target.URL,
			"generated_at":   r.GeneratedAt,
			"duration":       r.Duration,
			"workers":        r.Workers,
			"summary":        r.Summary,
			"open_ports":     len(r.PortScan),
			"http_discovery": len(r.HTTPDiscovery),
			"top_5_critical": topFindings(r.Findings, 5),
			"threat_intel":   r.ThreatIntel,
			"waf":            r.WAF,
		})
	}
}

func (s *Server) handleDeleteReport(ctx context.Context, req *mcp.CallToolRequest, in DeleteReportInput) (*mcp.CallToolResult, any, error) {
	if in.ID == "" {
		return errorResult("id is required"), nil, nil
	}
	if err := s.store.Delete(in.ID); err != nil {
		return errorResult(err.Error()), nil, nil
	}
	if s.lastReport == in.ID {
		s.lastReport = ""
	}
	return jsonResult(map[string]any{"deleted": in.ID})
}

func (s *Server) handleExploit(ctx context.Context, req *mcp.CallToolRequest, in ExploitInput) (*mcp.CallToolResult, any, error) {
	var findings []models.Finding
	if in.ID != "" {
		r, err := s.store.Get(in.ID)
		if err != nil {
			return errorResult(err.Error()), nil, nil
		}
		findings = r.Findings
	} else {
		for _, m := range s.store.List("") {
			r, err := s.store.Get(m.ID)
			if err != nil {
				continue
			}
			findings = append(findings, r.Findings...)
		}
	}

	minSev := models.SeverityInfo
	if in.Severity != "" {
		minSev = models.Severity(strings.ToUpper(in.Severity))
	}

	type guide struct {
		Finding     models.Finding      `json:"finding"`
		Exploit     string              `json:"exploit"`
		Remediation string              `json:"remediation"`
		Exploits    []models.ExploitRef `json:"exploits,omitempty"`
	}
	out := []guide{}
	for _, f := range findings {
		if f.Severity.Score() < minSev.Score() {
			continue
		}
		if in.Category != "" && !strings.EqualFold(f.Category, in.Category) {
			continue
		}
		if in.Title != "" && !strings.Contains(strings.ToLower(f.Title), strings.ToLower(in.Title)) {
			continue
		}
		out = append(out, guide{Finding: f, Exploit: f.Exploit, Remediation: f.Remediation, Exploits: f.ExploitRefs})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Finding.Severity.Score() > out[j].Finding.Severity.Score()
	})
	max := in.MaxResults
	if max <= 0 {
		max = 5
	}
	if len(out) > max {
		out = out[:max]
	}
	return jsonResult(map[string]any{
		"count":  len(out),
		"guides": out,
		"tip":    "for deeper help ask apophis_check_cve with a specific service+version",
	})
}

// --- Auth / token attack handlers -----------------------------------------

func (s *Server) handleASREPRoast(ctx context.Context, req *mcp.CallToolRequest, in ASREPInput) (*mcp.CallToolResult, any, error) {
	if in.DC == "" {
		return errorResult("dc is required"), nil, nil
	}
	if in.Realm == "" {
		return errorResult("realm is required"), nil, nil
	}
	if len(in.Users) == 0 {
		return errorResult("users list is required (use apophis_ldap_audit to enumerate first)"), nil, nil
	}
	timeout := s.defaultTO
	if in.Timeout != "" {
		if d, err := time.ParseDuration(in.Timeout); err == nil {
			timeout = d
		}
	}
	det := adauth.NewASREPRoastDetector()
	det.Timeout = timeout
	results := det.Probe(ctx, in.DC, in.Realm, in.Users)
	findings := adauth.ToFindings(in.DC, results)
	return jsonResult(map[string]any{
		"dc":       in.DC,
		"realm":    in.Realm,
		"probed":   len(results),
		"results":  results,
		"findings": findings,
		"next":     "use hashcat -m 7500 to crack any crackable RC4-HMAC AS-REPs; the raw AS-REP bytes are in each RoastResult.Raw",
	})
}

func (s *Server) handleKerberoast(ctx context.Context, req *mcp.CallToolRequest, in KerberoastInput) (*mcp.CallToolResult, any, error) {
	// We don't drive an LDAP search here (that needs an LDAP server). We
	// surface the catalog + the prioritization logic + the workflow so the
	// operator can chain it with apophis_ldap_audit (or with the host's
	// own LDAP tooling) to produce the SPN list.
	return jsonResult(map[string]any{
		"info":     "This tool requires LDAP-discovered SPNs. Use apophis_ldap_audit (or external tooling like GetUserSPNs.py) to enumerate, then pass the list via apophis_kerberoast with an authenticated AS-REQ to retrieve the TGS for cracking.",
		"advisory": "The auth package provides the prioritization logic but does not perform AS-REQ preauth (TGT acquisition requires user-supplied credentials).",
		"next":     "Once you have a TGT, the apophis_poc_run tool can dispatch a Kerberoast PoC against the KDC.",
	})
}

func (s *Server) handleDelegationAudit(ctx context.Context, req *mcp.CallToolRequest, in DelegationInput) (*mcp.CallToolResult, any, error) {
	targets := adauth.EnumerateDelegation(in.UAC, in.Attrs)
	findings := adauth.DelegationToFindings("AD", targets)
	return jsonResult(map[string]any{
		"target":   "AD",
		"accounts": targets,
		"findings": findings,
		"tip":      "query msDS-AllowedToDelegateTo and msDS-AllowedToActOnBehalfOfOtherIdentity per account; pass userAccountControl as decimal per object",
	})
}

func (s *Server) handleNTLMDialects(ctx context.Context, req *mcp.CallToolRequest, in NTLMInput) (*mcp.CallToolResult, any, error) {
	if in.Target == "" {
		return errorResult("target is required"), nil, nil
	}
	timeout := s.defaultTO
	if in.Timeout != "" {
		if d, err := time.ParseDuration(in.Timeout); err == nil {
			timeout = d
		}
	}
	inspector := &adauth.NTLMInspector{Timeout: timeout}
	inspections := []adauth.Inspection{inspector.InspectSMB(ctx, in.Target, 445)}
	if in.URL != "" {
		inspections = append(inspections, inspector.InspectHTTP(ctx, in.URL))
	}
	findings := adauth.NTLMToFindings(in.Target, inspections)
	return jsonResult(map[string]any{
		"target":      in.Target,
		"inspections": inspections,
		"findings":    findings,
		"remediation": "Group Policy: Network security: LAN Manager authentication level = 'Send NTLMv2 response only. Refuse LM & NTLM.'",
	})
}

func (s *Server) handlePasswordPolicy(ctx context.Context, req *mcp.CallToolRequest, in PasswordPolicyInput) (*mcp.CallToolResult, any, error) {
	if len(in.Attrs) == 0 {
		return errorResult("attrs is required (LDAP Default Domain Policy attributes)"), nil, nil
	}
	p := adauth.ParseDomainPolicy(in.Attrs)
	findings := p.ToFindings("AD")
	return jsonResult(map[string]any{
		"policy":   p,
		"findings": findings,
	})
}

func (s *Server) handleSpray(ctx context.Context, req *mcp.CallToolRequest, in SprayInput) (*mcp.CallToolResult, any, error) {
	if in.Company == "" && in.Domain == "" {
		return errorResult("company or domain is required"), nil, nil
	}
	words := adauth.GenerateSprayWords(adauth.SprayConfig{
		Company:  in.Company,
		Domain:   in.Domain,
		Years:    in.Years,
		Include:  in.Include,
		MaxWords: in.MaxWords,
	})
	finding := adauth.ToFinding(in.Company+"."+in.Domain, words)
	return jsonResult(map[string]any{
		"company":  in.Company,
		"domain":   in.Domain,
		"wordlist": words,
		"finding":  finding,
		"tip":      "pipe the wordlist to apophis_poc_run with a password-spray PoC against OWA / ADFS / LDAP / Kerberos preauth (respect lockoutThreshold * 0.5)",
	})
}

func (s *Server) handleJWTAttack(ctx context.Context, req *mcp.CallToolRequest, in JWTInput) (*mcp.CallToolResult, any, error) {
	raw := strings.TrimSpace(in.Token)
	raw = strings.TrimPrefix(raw, "Bearer ")
	raw = strings.TrimPrefix(raw, "bearer ")
	if raw == "" {
		return errorResult("token is required"), nil, nil
	}
	j, err := tokens.DecodeJWT(raw)
	if err != nil {
		return errorResult("decode: " + err.Error()), nil, nil
	}
	findings := tokens.JWTInspect("jwt", in.Source, j)
	return jsonResult(map[string]any{
		"header":   j.Header,
		"payload":  j.Payload,
		"findings": findings,
	})
}

func (s *Server) handleJWTBrute(ctx context.Context, req *mcp.CallToolRequest, in JWTBruteInput) (*mcp.CallToolResult, any, error) {
	raw := strings.TrimSpace(in.Token)
	raw = strings.TrimPrefix(raw, "Bearer ")
	j, err := tokens.DecodeJWT(raw)
	if err != nil {
		return errorResult("decode: " + err.Error()), nil, nil
	}
	sec, ok := tokens.BruteForceJWTSecret(j)
	if !ok {
		return jsonResult(map[string]any{
			"matched":       false,
			"wordlist_size": len(tokens.WeakSecrets),
			"tip":           "secret not in bundled top-1000 — try a larger wordlist (jwt_tool.py / hashcat -m 16500)",
		})
	}
	return jsonResult(map[string]any{
		"matched": true,
		"secret":  sec,
		"finding": tokens.VerifyWeakSecretFinding("jwt", "brute", sec, j),
	})
}

func (s *Server) handleSAMLAttack(ctx context.Context, req *mcp.CallToolRequest, in SAMLInput) (*mcp.CallToolResult, any, error) {
	if in.Response == "" {
		return errorResult("response is required"), nil, nil
	}
	r, err := tokens.ParseSAMLResponse(in.Response)
	if err != nil {
		return errorResult("parse: " + err.Error()), nil, nil
	}
	findings := tokens.SAMLInspect("saml", in.Source, r)
	return jsonResult(map[string]any{
		"issuer":          r.Issuer,
		"destination":     r.Destination,
		"in_response_to":  r.InResponseTo,
		"signature_alg":   r.SignatureAlgo,
		"assertion_count": len(r.Assertions),
		"findings":        findings,
	})
}

func (s *Server) handleOAuthAudit(ctx context.Context, req *mcp.CallToolRequest, in OAuthInput) (*mcp.CallToolResult, any, error) {
	if in.AuthEndpoint == "" {
		return errorResult("auth_endpoint is required"), nil, nil
	}
	cfg := tokens.OAuthConfig{
		AuthEndpoint:     in.AuthEndpoint,
		RedirectURI:      in.RedirectURI,
		ClientID:         in.ClientID,
		Scopes:           in.Scopes,
		AllowedRedirects: in.AllowedRedirects,
	}
	findings := tokens.OAuthInspect("oauth", cfg)
	stateFindings := tokens.OAuthStateCheck("oauth", in.AuthEndpoint)
	findings = append(findings, stateFindings...)
	openRedirectFindings := tokens.OpenRedirectURLCheck("oauth", in.RedirectURI, in.AllowedRedirects)
	findings = append(findings, openRedirectFindings...)
	return jsonResult(map[string]any{
		"auth_endpoint": in.AuthEndpoint,
		"redirect_uri":  in.RedirectURI,
		"findings":      findings,
	})
}

func (s *Server) handleAuthAudit(ctx context.Context, mcpReq *mcp.CallToolRequest, in AuthAuditInput) (*mcp.CallToolResult, any, error) {
	if in.URL == "" {
		return errorResult("url is required"), nil, nil
	}
	timeout := s.defaultTO
	client := &http.Client{Timeout: timeout}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, in.URL, nil)
	if err != nil {
		return errorResult("request: " + err.Error()), nil, nil
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return errorResult("fetch: " + err.Error()), nil, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	bodyStr := string(body)

	findings := []models.Finding{}
	for _, f := range webauth.CookieAudit(in.URL, resp.Header, nil) {
		findings = append(findings, f)
	}
	if in.CSRFParam != "" {
		for _, f := range webauth.CSRFCheck(in.URL, bodyStr, in.CSRFParam) {
			findings = append(findings, f)
		}
	}
	if in.ResetHostTemplate != "" {
		for _, f := range webauth.ResetHostHeaderCheck(in.URL, in.ResetHostTemplate, in.URL) {
			findings = append(findings, f)
		}
	}
	for _, f := range webauth.RateLimitCheck(in.URL, resp.StatusCode, resp.Header.Get("Retry-After"), bodyStr, 5) {
		findings = append(findings, f)
	}
	for _, f := range credleak.NewEntropyDetector().Scan(in.URL, bodyStr) {
		findings = append(findings, f)
	}
	for _, f := range credleak.ScanHardcoded(in.URL, bodyStr) {
		findings = append(findings, f)
	}
	return jsonResult(map[string]any{
		"url":      in.URL,
		"status":   resp.StatusCode,
		"findings": findings,
	})
}

func (s *Server) handleCredLeak(ctx context.Context, mcpReq *mcp.CallToolRequest, in CredLeakInput) (*mcp.CallToolResult, any, error) {
	if in.URL == "" {
		return errorResult("url is required"), nil, nil
	}
	timeout := s.defaultTO
	client := &http.Client{Timeout: timeout}
	findings := []models.Finding{}

	// Fetch the base page (entropy + hardcoded creds).
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, in.URL, nil)
	if err == nil {
		if resp, err := client.Do(httpReq); err == nil {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
			resp.Body.Close()
			bodyStr := string(body)
			for _, f := range credleak.NewEntropyDetector().Scan(in.URL, bodyStr) {
				findings = append(findings, f)
			}
			for _, f := range credleak.ScanHardcoded(in.URL, bodyStr) {
				findings = append(findings, f)
			}
		}
	}

	// Backup-file scan + .git scan.
	base := strings.TrimRight(in.URL, "/")
	backupHits := map[string]credleak.BackupFileHit{}
	for _, f := range credleak.BackupFiles {
		if len(backupHits) > 200 {
			break
		}
		url := base + "/" + strings.TrimLeft(f.Path, "/")
		httpReq, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(httpReq)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		backupHits[f.Path] = credleak.BackupFileHit{Path: f.Path, Status: resp.StatusCode, BodySize: len(body), Body: string(body)}
	}
	for _, f := range credleak.BackupFileScan(in.URL, backupHits) {
		findings = append(findings, f)
	}
	gitHits := func(ctx context.Context, path string) (credleak.GitHit, error) {
		url := base + "/" + strings.TrimLeft(path, "/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return credleak.GitHit{}, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return credleak.GitHit{}, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return credleak.GitHit{Path: path, Status: resp.StatusCode, Size: len(body), Body: string(body)}, nil
	}
	for _, f := range credleak.GitScan(ctx, in.URL, gitHits) {
		findings = append(findings, f)
	}
	return jsonResult(map[string]any{
		"url":      in.URL,
		"findings": findings,
	})
}

func (s *Server) handleStatus(ctx context.Context, req *mcp.CallToolRequest, in RegisterInput) (*mcp.CallToolResult, any, error) {
	tiNames := []string{}
	for _, p := range s.tiProviders {
		tiNames = append(tiNames, p.Name())
	}
	return jsonResult(map[string]any{
		"server":             serverName,
		"version":            serverVersion,
		"store_dir":          s.store.Dir(),
		"reports_stored":     len(s.store.List("")),
		"dynamic_cves":       s.dynamic.Len(),
		"dynamic_path":       s.dynamic.Path(),
		"embeddings_indexed": s.embeddings.Len(),
		"research_sources":   s.agent.Names(),
		"threat_intel":       tiNames,
		"default_workers":    s.defaultW,
		"default_timeout":    s.defaultTO.String(),
		"last_report":        s.lastReport,
		"transport":          "stdio",
	})
}

func (s *Server) handleResearch(ctx context.Context, req *mcp.CallToolRequest, in ResearchInput) (*mcp.CallToolResult, any, error) {
	days := in.DaysBack
	if days <= 0 {
		days = 7
	}
	max := in.MaxPerSource
	if max <= 0 {
		max = 50
	}
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour)

	res, err := s.agent.Sync(ctx, in.Sources, since, max)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}
	// Refresh the embeddings index with any new entries.
	s.embeddings.Rebuild(s.dynamic.All())
	out := map[string]any{
		"started_at":     res.StartedAt,
		"finished_at":    res.FinishedAt,
		"duration":       res.Duration,
		"sources":        res.SourceStats,
		"total_fetched":  res.TotalFetched,
		"after_dedup":    res.AfterDedup,
		"added":          res.Added,
		"updated":        res.Updated,
		"top_findings":   res.TopFindings,
		"store_size":     s.dynamic.Len(),
		"embeddings_idx": s.embeddings.Len(),
	}
	if in.GenerateStubs {
		gen := research.NewGenerator("internal/tools/cve/generated")
		path, err := gen.Generate(s.dynamic.All())
		if err != nil {
			out["stub_error"] = err.Error()
		} else {
			out["stub_path"] = path
			out["next"] = fmt.Sprintf("review %s and rebuild (go build ./...) to bake the CVEs into the binary", path)
		}
	} else {
		out["next"] = "use apophis_search_cve / apophis_recent_cves / apophis_similar_cve to query what was found, or rerun with generate_stubs=true"
	}
	return jsonResult(out)
}

func (s *Server) handleSearchCVE(ctx context.Context, req *mcp.CallToolRequest, in SearchCVEInput) (*mcp.CallToolResult, any, error) {
	q := dynamic.SearchQuery{
		Keyword:  in.Keyword,
		MinCVSS:  in.MinCVSS,
		Severity: in.Severity,
		OnlyKEV:  in.OnlyKEV,
		Limit:    in.Limit,
	}
	if q.Limit <= 0 {
		q.Limit = 25
	}
	results := s.dynamic.Search(q)
	return jsonResult(map[string]any{
		"query":   in,
		"count":   len(results),
		"results": results,
	})
}

func (s *Server) handleRecentCVE(ctx context.Context, req *mcp.CallToolRequest, in RecentCVEInput) (*mcp.CallToolResult, any, error) {
	days := in.Days
	if days <= 0 {
		days = 30
	}
	since := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	limit := in.Limit
	if limit <= 0 {
		limit = 25
	}
	q := dynamic.SearchQuery{
		MinCVSS: in.MinCVSS,
		OnlyKEV: in.OnlyKEV,
		Since:   &since,
		Limit:   limit,
	}
	results := s.dynamic.Search(q)
	return jsonResult(map[string]any{
		"days_back": days,
		"min_cvss":  in.MinCVSS,
		"only_kev":  in.OnlyKEV,
		"count":     len(results),
		"results":   results,
		"tip":       "for similarity search use apophis_similar_cve with a free-text description",
	})
}

func (s *Server) handleGenerateStub(ctx context.Context, req *mcp.CallToolRequest, in GenerateStubInput) (*mcp.CallToolResult, any, error) {
	if in.CVE == "" {
		return errorResult("cve is required"), nil, nil
	}
	for _, e := range s.dynamic.All() {
		if e.CVE == in.CVE {
			stub := research.StubFor(e)
			return jsonResult(map[string]any{
				"cve":        e.CVE,
				"title":      e.Title,
				"service":    e.Service,
				"version":    e.Version,
				"cvss":       e.CVSS,
				"stub":       stub,
				"how_to_use": "append the function to internal/tools/cve/cve.go and call it from the Matcher.Match loop",
			})
		}
	}
	return errorResult("CVE " + in.CVE + " not found in dynamic store; run apophis_research first"), nil, nil
}

func (s *Server) handlePoCList(ctx context.Context, req *mcp.CallToolRequest, in PoCListInput) (*mcp.CallToolResult, any, error) {
	if s.exec == nil || s.exec.Executor == nil {
		return errorResult("PoC executor is not enabled (start the server with -enable-executor)"), nil, nil
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 25
	}
	min := poc.ParseRisk(in.MinRisk)
	max := poc.ParseRisk(in.MaxRisk)
	if min < 0 {
		min = -1
	}
	if max < 0 {
		max = poc.RiskDestructive
	}
	results := s.exec.Executor.ListPoCs(in.CVE, in.Source, min, max, limit)
	out := make([]map[string]any, 0, len(results))
	for _, p := range results {
		out = append(out, pocSummary(p))
	}
	return jsonResult(map[string]any{
		"count":    len(out),
		"results":  out,
		"executor": s.exec.Config.Enabled,
		"max_risk": s.exec.Config.MaxRisk.String(),
		"tip":      "use apophis_poc_preview before apophis_poc_run to see the exact command",
	})
}

func (s *Server) handlePoCPreview(ctx context.Context, req *mcp.CallToolRequest, in struct {
	PoCID        string `json:"poc_id"`
	Target       string `json:"target"`
	SandboxLevel string `json:"sandbox_level,omitempty"`
	TimeoutSec   int    `json:"timeout_sec,omitempty"`
}) (*mcp.CallToolResult, any, error) {
	if s.exec == nil || s.exec.Executor == nil {
		return errorResult("PoC executor is not enabled"), nil, nil
	}
	if in.PoCID == "" {
		return errorResult("poc_id is required"), nil, nil
	}
	if in.Target == "" {
		return errorResult("target is required"), nil, nil
	}
	poC, err := s.exec.Executor.GetPoC(in.PoCID)
	if err != nil {
		return errorResult("PoC not found: " + err.Error()), nil, nil
	}
	req2 := poc.RunRequest{
		PoC:          poC,
		Target:       in.Target,
		SandboxLevel: poc.SandboxLevel(in.SandboxLevel),
		TimeoutSec:   in.TimeoutSec,
		Confirm:      true,
	}
	res, err := s.exec.Executor.Preview(req2)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}
	return jsonResult(map[string]any{
		"poc":           pocSummary(poC),
		"target":        in.Target,
		"sandbox_level": res.SandboxLevel,
		"sandbox_info":  res.SandboxInfo,
		"dry_run":       res.DryRun,
		"preview_only":  true,
		"stdout":        res.Stdout,
		"next":          "if the command looks right, call apophis_poc_run with confirm:true",
	})
}

func (s *Server) handlePoCRun(ctx context.Context, req *mcp.CallToolRequest, in PoCRunInput) (*mcp.CallToolResult, any, error) {
	if s.exec == nil || s.exec.Executor == nil {
		return errorResult("PoC executor is not enabled (start the server with -enable-executor)"), nil, nil
	}
	if in.PoCID == "" {
		return errorResult("poc_id is required"), nil, nil
	}
	if in.Target == "" {
		return errorResult("target is required"), nil, nil
	}
	if !in.Confirm {
		return errorResult("confirm:true (literal boolean) is required to run a PoC — refuse to execute"), nil, nil
	}
	poC, err := s.exec.Executor.GetPoC(in.PoCID)
	if err != nil {
		return errorResult("PoC not found: " + err.Error()), nil, nil
	}
	rreq := poc.RunRequest{
		PoC:          poC,
		Target:       in.Target,
		SandboxLevel: poc.SandboxLevel(in.SandboxLevel),
		TimeoutSec:   in.TimeoutSec,
		Confirm:      in.Confirm,
		ExtraArgs:    in.ExtraArgs,
		UserNote:     in.UserNote,
	}
	res, err := s.exec.Executor.Run(ctx, rreq)
	if err != nil {
		return errorResult("execution failed: " + err.Error()), nil, nil
	}
	return jsonResult(map[string]any{
		"execution_id":     res.ExecutionID,
		"started_at":       res.StartedAt,
		"finished_at":      res.FinishedAt,
		"duration_ms":      res.DurationMs,
		"target":           in.Target,
		"poc":              pocSummary(poC),
		"sandbox_level":    res.SandboxLevel,
		"sandboxed":        res.Sandboxed,
		"exit_code":        res.ExitCode,
		"signal":           res.Signal,
		"stdout":           res.Stdout,
		"stderr":           res.Stderr,
		"exploit_verified": res.ExploitVerified,
		"vuln_confirmed":   res.VulnConfirmed,
		"dry_run":          res.DryRun,
		"next":             "use apophis_poc_history to inspect all past executions, or apophis_poc_kill to abort if still running",
	})
}

func (s *Server) handlePoCAllowlist(ctx context.Context, req *mcp.CallToolRequest, in PoCAllowlistInput) (*mcp.CallToolResult, any, error) {
	if s.exec == nil || s.exec.Allowlist == nil {
		return errorResult("PoC executor is not enabled"), nil, nil
	}
	switch in.Action {
	case "list":
		return jsonResult(map[string]any{
			"count":   s.exec.Allowlist.Len(),
			"entries": s.exec.Allowlist.List(),
		})
	case "add":
		if in.Target == "" {
			return errorResult("target is required to add"), nil, nil
		}
		if err := s.exec.Allowlist.Add(in.Target, in.Note); err != nil {
			return errorResult(err.Error()), nil, nil
		}
		return jsonResult(map[string]any{"added": in.Target, "note": in.Note})
	case "remove":
		if in.Target == "" {
			return errorResult("target is required to remove"), nil, nil
		}
		if !s.exec.Allowlist.Remove(in.Target) {
			return errorResult("target not in allowlist: " + in.Target), nil, nil
		}
		return jsonResult(map[string]any{"removed": in.Target})
	default:
		return errorResult("action must be one of: list, add, remove"), nil, nil
	}
}

func (s *Server) handlePoCKill(ctx context.Context, req *mcp.CallToolRequest, in PoCKillInput) (*mcp.CallToolResult, any, error) {
	if s.exec == nil || s.exec.Executor == nil {
		return errorResult("PoC executor is not enabled"), nil, nil
	}
	if in.ExecutionID == "" {
		return errorResult("execution_id is required"), nil, nil
	}
	if err := s.exec.Executor.Kill(in.ExecutionID); err != nil {
		return errorResult(err.Error()), nil, nil
	}
	return jsonResult(map[string]any{"killed": in.ExecutionID})
}

func (s *Server) handlePoCHistory(ctx context.Context, req *mcp.CallToolRequest, in PoCHistoryInput) (*mcp.CallToolResult, any, error) {
	if s.exec == nil || s.exec.Audit == nil {
		return errorResult("PoC executor is not enabled"), nil, nil
	}
	limit := in.Limit
	if limit <= 0 {
		limit = 50
	}
	var since time.Time
	if in.Since != "" {
		if t, err := time.Parse(time.RFC3339, in.Since); err == nil {
			since = t
		}
	}
	entries, err := s.exec.Audit.List(since, in.Target, limit)
	if err != nil {
		return errorResult(err.Error()), nil, nil
	}
	return jsonResult(map[string]any{
		"count":   len(entries),
		"entries": entries,
		"note":    "all entries are HMAC-signed; tampering is detected on read",
	})
}

func pocSummary(p *poc.PoC) map[string]any {
	return map[string]any{
		"id":           p.ID,
		"cve":          p.CVE,
		"source":       p.Source,
		"title":        p.Title,
		"type":         p.Type,
		"risk":         p.Risk.String(),
		"requires_net": p.RequiresNet,
		"signature":    p.Signature,
		"args":         p.Args,
		"created_at":   p.CreatedAt,
	}
}

func parsePorts(s string) []int {
	out := []int{}
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		var n int
		fmt.Sscanf(p, "%d", &n)
		if n > 0 && n < 65536 {
			out = append(out, n)
		}
	}
	return out
}

func bySev(s models.Summary) map[string]int {
	return map[string]int{
		"CRITICAL": s.Critical,
		"HIGH":     s.High,
		"MEDIUM":   s.Medium,
		"LOW":      s.Low,
		"INFO":     s.Info,
	}
}

func topFindings(findings []models.Finding, n int) []findingBrief {
	out := []findingBrief{}
	for _, f := range findings {
		out = append(out, findingBrief{
			Title:    f.Title,
			Severity: string(f.Severity),
			Category: f.Category,
			Target:   f.Target,
			Exploit:  f.Exploit,
			CVE:      strings.Join(f.CVE, ","),
		})
		if len(out) >= n {
			break
		}
	}
	return out
}

func sevFromHeader(h string) models.Severity {
	l := strings.ToLower(h)
	if strings.Contains(l, "information disclosure") {
		return models.SeverityInfo
	}
	return models.SeverityLow
}

func jsonResult(v any) (*mcp.CallToolResult, any, error) {
	b, _ := json.MarshalIndent(v, "", "  ")
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(b)}},
	}, nil, nil
}

func errorResult(msg string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: "ERROR: " + msg}},
		IsError: true,
	}
}

var _ = ssl.NewSSLTester
var _ = http.Client{}
