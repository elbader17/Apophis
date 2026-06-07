package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/apophis-eng/apophis/internal/logger"
	"github.com/apophis-eng/apophis/internal/models"
	"github.com/apophis-eng/apophis/internal/orchestrator"
	"github.com/apophis-eng/apophis/internal/research"
	"github.com/apophis-eng/apophis/internal/store"
	"github.com/apophis-eng/apophis/internal/tools/cve"
	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
	"github.com/apophis-eng/apophis/internal/tools/network"
	"github.com/apophis-eng/apophis/internal/tools/ssl"
	"github.com/apophis-eng/apophis/internal/tools/web"
)

const serverName = "apophis"
const serverVersion = "0.1.0"

type Server struct {
	store      *store.Store
	dynamic    *dynamic.Store
	agent      *research.Agent
	defaultW   int
	defaultTO  time.Duration
	lastReport string
}

type AuditInput struct {
	Target   string `json:"target" jsonschema:"hostname or IP to audit"`
	URL      string `json:"url,omitempty" jsonschema:"optional base URL"`
	Workers  int    `json:"workers,omitempty" jsonschema:"number of parallel agents (1-16)"`
	Timeout  string `json:"timeout,omitempty" jsonschema:"per-probe timeout like '5s'"`
	Ports    string `json:"ports,omitempty" jsonschema:"comma-separated ports, blank for top common"`
	Strategy string `json:"strategy,omitempty" jsonschema:"force a single strategy for all workers (recon,aggressive,stealth,web-focus,net-focus,auth-focus)"`
}

type PortScanInput struct {
	Target  string `json:"target" jsonschema:"hostname or IP to scan"`
	Ports   string `json:"ports,omitempty" jsonschema:"comma-separated ports"`
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

type ListReportsInput struct {
	Target string `json:"target,omitempty" jsonschema:"filter by target substring"`
	Limit  int    `json:"limit,omitempty" jsonschema:"max results (default 20)"`
}

type GetReportInput struct {
	ID    string `json:"id" jsonschema:"report id returned by audit_target"`
	Format string `json:"format,omitempty" jsonschema:"json|summary|findings (default: summary)"`
}

type DeleteReportInput struct {
	ID string `json:"id" jsonschema:"report id to delete"`
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
	Keyword string  `json:"keyword,omitempty" jsonschema:"search keyword (CVE id, vendor, product, title)"`
	MinCVSS float64 `json:"min_cvss,omitempty" jsonschema:"minimum CVSS score (e.g. 7.0)"`
	Severity string `json:"severity,omitempty" jsonschema:"exact severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)"`
	OnlyKEV bool    `json:"only_kev,omitempty" jsonschema:"only CISA KEV (known-exploited) entries"`
	Limit   int     `json:"limit,omitempty" jsonschema:"max results (default 25)"`
}

type RecentCVEInput struct {
	Days   int     `json:"days,omitempty" jsonschema:"only show CVEs from the last N days (default 30)"`
	MinCVSS float64 `json:"min_cvss,omitempty" jsonschema:"minimum CVSS score (default 0)"`
	Limit  int     `json:"limit,omitempty" jsonschema:"max results (default 25)"`
	OnlyKEV bool   `json:"only_kev,omitempty" jsonschema:"only CISA KEV entries"`
}

type GenerateStubInput struct {
	CVE string `json:"cve" jsonschema:"CVE id to generate a Go check stub for"`
}

func NewServer(s *store.Store, dyn *dynamic.Store, agent *research.Agent, defaultWorkers int, defaultTimeout time.Duration) *Server {
	return &Server{store: s, dynamic: dyn, agent: agent, defaultW: defaultWorkers, defaultTO: defaultTimeout}
}

func (s *Server) Register(server *mcp.Server) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_audit",
		Description: "Run a full multi-strategy parallel vulnerability audit against a target. Spawns multiple chaos agents that race to find weaknesses. Returns a report id and a summary of findings.",
	}, s.handleAudit)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_portscan",
		Description: "Quick TCP port scan with banner grabbing. No exploitation checks, just port discovery and service identification.",
	}, s.handlePortScan)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_web_audit",
		Description: "Focused web application audit. Checks security headers, exposed paths, common web vulns (LFI/SQLi/XSS if deep=true), and TLS.",
	}, s.handleWebAudit)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_check_cve",
		Description: "Match a service+version+banner against the local CVE database. Returns any known critical CVEs (EternalBlue, BlueKeep, Log4Shell, Heartbleed, ProxyLogon, Zerologon, etc.) with CVSS, exploit and remediation.",
	}, s.handleCheckCVE)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_list_reports",
		Description: "List all stored vulnerability reports. Optionally filter by target substring.",
	}, s.handleListReports)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_get_report",
		Description: "Retrieve a stored report by id. Format can be 'summary' (default), 'findings' (full list), or 'json' (raw).",
	}, s.handleGetReport)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_delete_report",
		Description: "Delete a stored report and its markdown counterpart.",
	}, s.handleDeleteReport)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_recommend_exploitation",
		Description: "Look up exploitation guidance (commands, Metasploit modules, manual steps) for findings, optionally filtered by report id, title, category or minimum severity.",
	}, s.handleExploit)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_status",
		Description: "Show Apophis server status: version, store path, default settings, last report id.",
	}, s.handleStatus)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_research",
		Description: "Sync the latest CVEs from public vulnerability databases (NVD, CISA KEV, OSV, Exploit-DB, GitHub Security Advisories, security RSS feeds). Updates the dynamic CVE database. Returns per-source stats and top findings.",
	}, s.handleResearch)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_search_cve",
		Description: "Search the dynamic CVE database by keyword, minimum CVSS, severity or KEV-only filter. Useful after apophis_research to query what was found.",
	}, s.handleSearchCVE)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_recent_cves",
		Description: "Show the most recent CVEs from the dynamic database, optionally filtered by date and CVSS.",
	}, s.handleRecentCVE)

	mcp.AddTool(server, &mcp.Tool{
		Name:        "apophis_generate_stub",
		Description: "Generate a Go check stub for a given CVE that can be pasted into the static database. Use after apophis_research to promote a critical CVE to a permanent check.",
	}, s.handleGenerateStub)
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

	logger.Info("apophis_audit", fmt.Sprintf("target=%s workers=%d timeout=%s", t.Host, workers, to))

	orch := orchestrator.New(t, workers)
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
		ReportID:   id,
		Target:     t.Host,
		URL:        r.Target.URL,
		Duration:   r.Duration,
		Workers:    r.Workers,
		RiskScore:  r.Summary.RiskScore,
		Total:      r.Summary.Total,
		BySeverity: bySev(r.Summary),
		TopFindings: topFindings(r.Findings, 5),
		OpenPorts:  len(r.PortScan),
		HTTPDiscovery: len(r.HTTPDiscovery),
		Next:       "use apophis_get_report with id=" + id + " (format=findings) for full list, or apophis_recommend_exploitation to see exploit commands",
	}
	return jsonResult(out)
}

type auditOutput struct {
	ReportID      string         `json:"report_id"`
	Target        string         `json:"target"`
	URL           string         `json:"url"`
	Duration      string         `json:"duration"`
	Workers       int            `json:"workers"`
	RiskScore     int            `json:"risk_score"`
	Total         int            `json:"total"`
	BySeverity    map[string]int `json:"by_severity"`
	TopFindings   []findingBrief `json:"top_findings"`
	OpenPorts     int            `json:"open_ports"`
	HTTPDiscovery int            `json:"http_discovery"`
	Next          string         `json:"next_steps"`
}

type findingBrief struct {
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Category  string `json:"category"`
	Target    string `json:"target"`
	Exploit   string `json:"exploit"`
	CVE       string `json:"cve,omitempty"`
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
	results := ps.Scan(ctx, in.Target, ports)
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })

	return jsonResult(map[string]any{
		"target":  in.Target,
		"scanned": len(ports),
		"open":    len(results),
		"ports":   results,
	})
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

	return jsonResult(map[string]any{
		"url":          in.URL,
		"status":       info.StatusCode,
		"server":       info.Server,
		"title":        info.Title,
		"headers":      info.Headers,
		"tls":          info.TLS,
		"findings":     findings,
		"findings_n":   len(findings),
	})
}

func (s *Server) handleCheckCVE(ctx context.Context, req *mcp.CallToolRequest, in CheckCVEInput) (*mcp.CallToolResult, any, error) {
	if in.Service == "" {
		return errorResult("service is required"), nil, nil
	}
	m := cve.New().WithDynamic(s.dynamic)
	findings := m.Match(in.Service, in.Version, in.Banner)
	return jsonResult(map[string]any{
		"service":     in.Service,
		"version":     in.Version,
		"matched":     len(findings),
		"findings":    findings,
		"db_static":   14,
		"db_dynamic":  s.dynamic.Len(),
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
			"report_id":     in.ID,
			"target":        r.Target.Host,
			"generated_at":  r.GeneratedAt,
			"summary":       r.Summary,
			"port_scan":     r.PortScan,
			"http_discovery": r.HTTPDiscovery,
			"findings":      r.Findings,
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
		Finding     models.Finding `json:"finding"`
		Exploit     string         `json:"exploit"`
		Remediation string         `json:"remediation"`
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
		out = append(out, guide{Finding: f, Exploit: f.Exploit, Remediation: f.Remediation})
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
		"count":   len(out),
		"guides":  out,
		"tip":     "for deeper help ask apophis_check_cve with a specific service+version",
	})
}

func (s *Server) handleStatus(ctx context.Context, req *mcp.CallToolRequest, in RegisterInput) (*mcp.CallToolResult, any, error) {
	return jsonResult(map[string]any{
		"server":          serverName,
		"version":         serverVersion,
		"store_dir":       s.store.Dir(),
		"reports_stored":  len(s.store.List("")),
		"dynamic_cves":    s.dynamic.Len(),
		"dynamic_path":    s.dynamic.Path(),
		"research_sources": s.agent.Names(),
		"default_workers": s.defaultW,
		"default_timeout": s.defaultTO.String(),
		"last_report":     s.lastReport,
		"transport":       "stdio",
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
	out := map[string]any{
		"started_at":    res.StartedAt,
		"finished_at":   res.FinishedAt,
		"duration":      res.Duration,
		"sources":       res.SourceStats,
		"total_fetched": res.TotalFetched,
		"after_dedup":   res.AfterDedup,
		"added":         res.Added,
		"updated":       res.Updated,
		"top_findings":  res.TopFindings,
		"store_size":    s.dynamic.Len(),
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
		out["next"] = "use apophis_search_cve / apophis_recent_cves to query what was found, or rerun with generate_stubs=true"
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
		"days_back":  days,
		"min_cvss":   in.MinCVSS,
		"only_kev":   in.OnlyKEV,
		"count":      len(results),
		"results":    results,
		"tip":        "for deeper analysis ask apophis_check_cve with service+version+specific values",
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
				"cve":     e.CVE,
				"title":   e.Title,
				"service": e.Service,
				"version": e.Version,
				"cvss":    e.CVSS,
				"stub":    stub,
				"how_to_use": "append the function to internal/tools/cve/cve.go and call it from the Matcher.Match loop",
			})
		}
	}
	return errorResult("CVE " + in.CVE + " not found in dynamic store; run apophis_research first"), nil, nil
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
