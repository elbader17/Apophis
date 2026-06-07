package worker

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/apophis-eng/apophis/internal/logger"
	"github.com/apophis-eng/apophis/internal/models"
	"github.com/apophis-eng/apophis/internal/tools/auth"
	"github.com/apophis-eng/apophis/internal/tools/cve"
	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
	"github.com/apophis-eng/apophis/internal/tools/network"
	"github.com/apophis-eng/apophis/internal/tools/ssl"
	"github.com/apophis-eng/apophis/internal/tools/web"
)

type Worker struct {
	ID       string
	Strategy models.Strategy
	Dynamic  *dynamic.Store
}

type Result struct {
	WorkerID string
	Strategy models.Strategy
	Findings []models.Finding
	Ports    []models.PortInfo
	HTTPInfo []models.HTTPInfo
	Duration time.Duration
	Err      error
}

func (w *Worker) Run(ctx context.Context, t models.Target, portSem chan struct{}) Result {
	start := time.Now()
	res := Result{WorkerID: w.ID, Strategy: w.Strategy}
	logger.Info(w.ID, fmt.Sprintf("awakening with strategy=%s", w.Strategy))

	ports, err := w.phasePortScan(ctx, t, portSem)
	if err != nil {
		res.Err = err
		return res
	}
	res.Ports = ports
	logger.Success(w.ID, fmt.Sprintf("port scan complete: %d open ports", len(ports)))

	sslFindings, sslInfos := w.phaseSSL(ctx, t, ports)
	res.Findings = append(res.Findings, sslFindings...)
	_ = sslInfos

	httpInfo, webFindings := w.phaseWeb(ctx, t, ports)
	res.HTTPInfo = httpInfo
	res.Findings = append(res.Findings, webFindings...)

	authFindings := w.phaseAuth(ctx, t, httpInfo)
	res.Findings = append(res.Findings, authFindings...)

	cveFindings := w.phaseCVE(ports, httpInfo, res.Findings)
	res.Findings = append(res.Findings, cveFindings...)

	res.Findings = deduplicate(res.Findings)
	for i := range res.Findings {
		res.Findings[i].WorkerID = w.ID
		res.Findings[i].Strategy = w.Strategy
		if res.Findings[i].DetectedAt.IsZero() {
			res.Findings[i].DetectedAt = time.Now()
		}
		if res.Findings[i].ID == "" {
			res.Findings[i].ID = buildID(w.ID, res.Findings[i])
		}
	}

	res.Duration = time.Since(start)
	logger.Info(w.ID, fmt.Sprintf("finished in %s with %d findings", res.Duration.Round(time.Millisecond), len(res.Findings)))
	return res
}

func (w *Worker) phasePortScan(ctx context.Context, t models.Target, portSem chan struct{}) ([]models.PortInfo, error) {
	if !w.shouldRun("portscan") {
		return nil, nil
	}
	ps := network.NewPortScanner(t.Timeout)
	ports := t.Ports
	if w.Strategy == models.StrategyStealth {
		ports = []int{21, 22, 23, 25, 80, 110, 139, 143, 443, 445, 3389, 3306, 5432, 8080, 8443}
	}
	if w.Strategy == models.StrategyRecon {
		ports = []int{21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017}
	}
	open := ps.Scan(ctx, t.Host, ports)
	return open, nil
}

func (w *Worker) phaseSSL(ctx context.Context, t models.Target, ports []models.PortInfo) ([]models.Finding, []models.TLSInfo) {
	if !w.shouldRun("ssl") {
		return nil, nil
	}
	tester := ssl.NewSSLTester(t.Timeout)
	infos := []models.TLSInfo{}
	findings := []models.Finding{}
	for _, p := range ports {
		if p.Service != "https" && p.Service != "https-alt" && p.Port != 443 && p.Port != 8443 {
			continue
		}
		info := tester.Inspect(ctx, t.Host, p.Port)
		if info == nil {
			continue
		}
		infos = append(infos, *info)
		for _, issue := range info.Issues {
			sev := models.SeverityMedium
			if info.SelfSigned {
				sev = models.SeverityLow
			}
			if strings.Contains(issue, "Weak") || strings.Contains(issue, "Deprecated") {
				sev = models.SeverityHigh
			}
			findings = append(findings, models.Finding{
				Title:       fmt.Sprintf("TLS issue on %s:%d — %s", t.Host, p.Port, issue),
				Severity:    sev,
				Category:    "TLS/SSL",
				Target:      fmt.Sprintf("%s:%d", t.Host, p.Port),
				Port:        p.Port,
				Evidence:    fmt.Sprintf("TLS=%s Cipher=%s SelfSigned=%v Expires=%s", info.Version, info.Cipher, info.SelfSigned, info.Expires),
				Description: fmt.Sprintf("The TLS service at %s:%d presents: %s. Cipher %s on %s.", t.Host, p.Port, issue, info.Cipher, info.Version),
				Exploit:     "Use testssl.sh or sslyze to enumerate weak ciphers and protocol versions.",
				Remediation: "Disable TLS 1.0/1.1, configure strong ciphers (AEAD), renew certificates before expiry.",
				References:  []string{"https://owasp.org/www-project-top-ten/2017/A6_2017-Security_Misconfiguration"},
			})
		}
	}
	return findings, infos
}

func (w *Worker) phaseWeb(ctx context.Context, t models.Target, ports []models.PortInfo) ([]models.HTTPInfo, []models.Finding) {
	if !w.shouldRun("web") {
		return nil, nil
	}
	ws := web.NewWebScanner(t.Timeout)
	info := []models.HTTPInfo{}
	if t.URL != "" {
		if h, err := ws.Fetch(ctx, t.URL); err == nil && h.StatusCode > 0 {
			info = append(info, *h)
		}
		alt := ensureScheme(t.URL, "https")
		if h, err := ws.Fetch(ctx, alt); err == nil && h.StatusCode > 0 && h.StatusCode != 404 {
			info = append(info, *h)
		}
	}
	scanPorts := portInts(ports)
	if len(scanPorts) == 0 && t.URL == "" {
		info = append(info, ws.Discover(ctx, t.Host, nil)...)
	} else if len(scanPorts) > 0 {
		for _, h := range ws.Discover(ctx, t.Host, scanPorts) {
			already := false
			for _, existing := range info {
				if existing.URL == h.URL {
					already = true
					break
				}
			}
			if !already {
				info = append(info, h)
			}
		}
	}
	findings := []models.Finding{}

	discovery := web.NewDiscovery(ws.Client())
	for _, h := range info {
		if h.StatusCode == 0 || h.StatusCode >= 500 {
			continue
		}
		base := h.URL
		if w.Strategy != models.StrategyRecon {
			findings = append(findings, discovery.BrutePaths(ctx, base)...)
		}
	}

	for _, h := range info {
		if h.StatusCode == 0 {
			continue
		}
		if h.StatusCode >= 500 {
			findings = append(findings, models.Finding{
				Title:       fmt.Sprintf("Server error 5xx on %s", h.URL),
				Severity:    models.SeverityLow,
				Category:    "Web",
				Target:      h.URL,
				Evidence:    fmt.Sprintf("HTTP %d", h.StatusCode),
				Description: "Server returned a 5xx error. Could indicate unstable service or verbose error pages.",
				Exploit:     "Trigger error with malformed input to leak stack traces or framework versions.",
				Remediation: "Configure production error pages, disable debug mode.",
			})
		}
		for _, h2 := range ws.CheckSecurityHeaders(h.Headers) {
			sev := models.SeverityLow
			if strings.Contains(h2, "Information disclosure") {
				sev = models.SeverityInfo
			}
			findings = append(findings, models.Finding{
				Title:       h2,
				Severity:    sev,
				Category:    "Web",
				Target:      h.URL,
				Evidence:    h2,
				Description: fmt.Sprintf("Web server at %s is missing best-practice security headers or exposing version info.", h.URL),
				Exploit:     "Absence of headers enables clickjacking, MIME sniffing, referrer leakage, downgrade attacks.",
				Remediation: "Set Strict-Transport-Security, X-Frame-Options DENY, X-Content-Type-Options nosniff, Content-Security-Policy, Referrer-Policy strict-origin-when-cross-origin.",
				References:  []string{"https://owasp.org/www-project-secure-headers/"},
			})
		}
		if w.Strategy == models.StrategyAggressive || w.Strategy == models.StrategyWebFocus {
			for _, e := range ws.CheckDirectoryTraversal(ctx, h.URL) {
				findings = append(findings, models.Finding{
					Title:       "Local File Inclusion / Directory Traversal",
					Severity:    models.SeverityCritical,
					Category:    "Web",
					Target:      h.URL,
					Evidence:    e,
					Description: "The web application appears to be vulnerable to path traversal, allowing reading of arbitrary files on the server.",
					Exploit:     "Use ../../../../etc/passwd or URL-encoded variants; chain with file read primitives for credential extraction.",
					Remediation: "Sanitize and validate user-supplied path input; use allow-lists for file access.",
					References:  []string{"https://owasp.org/www-community/attacks/Path_Traversal"},
				})
			}
			for _, e := range ws.CheckSQLInjection(ctx, h.URL) {
				findings = append(findings, models.Finding{
					Title:       "SQL Injection (reflected)",
					Severity:    models.SeverityCritical,
					Category:    "Web",
					Target:      h.URL,
					Evidence:    e,
					Description: "The web application leaks database error messages, a strong indicator of SQL injection vulnerability.",
					Exploit:     "Use sqlmap -u \"URL\" --batch --dbs to enumerate databases automatically.",
					Remediation: "Use parameterized queries / prepared statements. Never concatenate user input into SQL strings.",
					References:  []string{"https://owasp.org/www-community/attacks/SQL_Injection"},
				})
			}
			for _, e := range ws.CheckXSS(ctx, h.URL) {
				findings = append(findings, models.Finding{
					Title:       "Reflected Cross-Site Scripting (XSS)",
					Severity:    models.SeverityHigh,
					Category:    "Web",
					Target:      h.URL,
					Evidence:    e,
					Description: "User-supplied input is reflected back unsanitized in the HTML response.",
					Exploit:     "Craft a URL that executes arbitrary JavaScript in the victim's browser context for session theft or phishing.",
					Remediation: "Context-aware output encoding. Set Content-Security-Policy: default-src 'self'.",
					References:  []string{"https://owasp.org/www-community/attacks/xss/"},
				})
			}
		}
	}
	return info, findings
}

func (w *Worker) phaseAuth(ctx context.Context, t models.Target, httpInfo []models.HTTPInfo) []models.Finding {
	if !w.shouldRun("auth") {
		return nil
	}
	if w.Strategy == models.StrategyRecon {
		return nil
	}
	tester := auth.NewAuthTester(t.Timeout)
	findings := []models.Finding{}
	for _, h := range httpInfo {
		if h.StatusCode == 0 || h.StatusCode >= 500 {
			continue
		}
		if w.Strategy == models.StrategyStealth {
			continue
		}
		findings = append(findings, tester.TestDefaultCredentials(ctx, h.URL)...)
	}
	return findings
}

func (w *Worker) phaseCVE(ports []models.PortInfo, httpInfo []models.HTTPInfo, existing []models.Finding) []models.Finding {
	if !w.shouldRun("cve") {
		return nil
	}
	m := cve.New().WithDynamic(w.Dynamic)
	findings := []models.Finding{}
	for _, p := range ports {
		findings = append(findings, m.Match(p.Service, p.Version, p.Banner)...)
	}
	for _, h := range httpInfo {
		if h.Server != "" {
			findings = append(findings, m.Match("http", h.Server, h.Server)...)
		}
		if h.PoweredBy != "" {
			findings = append(findings, m.Match("http", h.PoweredBy, h.PoweredBy)...)
		}
	}
	return findings
}

func (w *Worker) shouldRun(phase string) bool {
	switch w.Strategy {
	case models.StrategyRecon:
		return phase == "portscan" || phase == "ssl" || phase == "web" || phase == "cve"
	case models.StrategyStealth:
		return phase == "portscan" || phase == "ssl" || phase == "web"
	case models.StrategyAggressive:
		return true
	case models.StrategyWebFocus:
		return phase == "portscan" || phase == "ssl" || phase == "web" || phase == "auth" || phase == "cve"
	case models.StrategyNetFocus:
		return phase == "portscan" || phase == "ssl" || phase == "cve"
	case models.StrategyAuthFocus:
		return phase == "portscan" || phase == "web" || phase == "auth"
	}
	return true
}

func ensureScheme(u, def string) string {
	if len(u) >= 7 && u[:7] == "http://" {
		return "https://" + u[7:]
	}
	if len(u) >= 8 && u[:8] == "https://" {
		return "http://" + u[8:]
	}
	return def + "://" + u
}

func portInts(ports []models.PortInfo) []int {
	out := make([]int, 0, len(ports))
	for _, p := range ports {
		out = append(out, p.Port)
	}
	return out
}

func deduplicate(findings []models.Finding) []models.Finding {
	seen := map[string]int{}
	out := make([]models.Finding, 0, len(findings))
	for _, f := range findings {
		k := dedupKey(f)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = 1
		out = append(out, f)
	}
	return out
}

func dedupKey(f models.Finding) string {
	return strings.ToLower(fmt.Sprintf("%s|%s|%s|%d", f.Category, f.Target, f.Title, f.Port))
}

func buildID(workerID string, f models.Finding) string {
	hash := 0
	for _, c := range dedupKey(f) {
		hash = hash*31 + int(c)
	}
	return fmt.Sprintf("%s-%x", workerID, hash&0xFFFF)
}

var mu sync.Mutex
var workerCounter int

func NewID(prefix string) string {
	mu.Lock()
	defer mu.Unlock()
	workerCounter++
	return fmt.Sprintf("%s-%02d", prefix, workerCounter)
}
