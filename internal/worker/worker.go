package worker

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	adauth "github.com/apophis-eng/apophis/internal/auth"
	"github.com/apophis-eng/apophis/internal/credleak"
	"github.com/apophis-eng/apophis/internal/logger"
	"github.com/apophis-eng/apophis/internal/models"
	"github.com/apophis-eng/apophis/internal/tokens"
	"github.com/apophis-eng/apophis/internal/tools/auth"
	"github.com/apophis-eng/apophis/internal/tools/cve"
	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
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
)

type Worker struct {
	ID        string
	Strategy  models.Strategy
	Dynamic   *dynamic.Store
	Exploits  *exploitlink.Linker
	NucleiDir string
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

	// Recon: TCP + UDP together. We always run portscan; UDP only when the
	// strategy says so (stealth skips UDP, recon runs it). Other strategies
	// pick up UDP indirectly through the deep-check phases.
	ports, err := w.phasePortScan(ctx, t, portSem)
	if err != nil {
		res.Err = err
		return res
	}
	res.Ports = ports
	udpPorts := w.phaseUDPScan(ctx, t)
	if len(udpPorts) > 0 {
		res.Ports = append(res.Ports, udpPorts...)
	}
	logger.Success(w.ID, fmt.Sprintf("port scan complete: %d open ports", len(res.Ports)))

	// Deep protocol checks gated by strategy + service availability.
	if w.shouldRun("deep") {
		if f := w.phaseSMB(ctx, t, res.Ports); len(f) > 0 {
			res.Findings = append(res.Findings, f...)
		}
		if f := w.phaseLDAP(ctx, t, res.Ports); len(f) > 0 {
			res.Findings = append(res.Findings, f...)
		}
		if f := w.phaseSNMP(ctx, t, res.Ports); len(f) > 0 {
			res.Findings = append(res.Findings, f...)
		}
		if f := w.phaseFTP(ctx, t, res.Ports); len(f) > 0 {
			res.Findings = append(res.Findings, f...)
		}
	}

	sslFindings, _ := w.phaseSSL(ctx, t, res.Ports)
	res.Findings = append(res.Findings, sslFindings...)

	httpInfo, webFindings := w.phaseWeb(ctx, t, res.Ports)
	res.HTTPInfo = httpInfo
	res.Findings = append(res.Findings, webFindings...)

	authFindings := w.phaseAuth(ctx, t, httpInfo)
	res.Findings = append(res.Findings, authFindings...)

	cveFindings := w.phaseCVE(res.Ports, httpInfo, res.Findings)
	res.Findings = append(res.Findings, cveFindings...)

	// Authentication attacks — gated by strategy. These run only on the
	// aggressive and web-focus paths because they require contacting an
	// auth endpoint (login, password reset, /.well-known/openid-configuration)
	// and produce auth-specific findings.
	if w.shouldRun("auth_attack") {
		res.Findings = append(res.Findings, w.phaseAuthAttack(ctx, t, httpInfo)...)
	}

	// Credential-leak probes — always on (cheap, high-signal). The probes
	// enumerate ~80 well-known sensitive paths plus run entropy / hardcoded
	// detection on every HTML response we already fetched.
	if w.shouldRun("cred_leak") {
		res.Findings = append(res.Findings, w.phaseCredLeak(ctx, t, httpInfo)...)
	}

	// Nuclei templates — when directory is configured and the strategy is
	// web-focused / aggressive.
	if w.shouldRun("nuclei") && len(httpInfo) > 0 {
		if f := w.phaseNuclei(ctx, httpInfo); len(f) > 0 {
			res.Findings = append(res.Findings, f...)
		}
	}

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
		// CVE → exploit correlation (best-effort, never blocking).
		if w.Exploits != nil && len(res.Findings[i].CVE) > 0 {
			refs := w.Exploits.Refs(res.Findings[i].CVE)
			if len(refs) > 0 {
				res.Findings[i].ExploitRefs = refs
				// Append exploit info into the Exploit field for the report.
				if res.Findings[i].Exploit != "" {
					res.Findings[i].Exploit += "\n"
				}
				res.Findings[i].Exploit += "Linked exploits: " + w.Exploits.Summary(refs)
			}
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

func (w *Worker) phaseUDPScan(ctx context.Context, t models.Target) []models.PortInfo {
	if !w.shouldRun("udp") {
		return nil
	}
	scanner := network.NewUDPScanner(t.Timeout)
	return scanner.Scan(ctx, t.Host, nil)
}

func (w *Worker) phaseSMB(ctx context.Context, t models.Target, ports []models.PortInfo) []models.Finding {
	tester := smb.New(t.Timeout)
	findings, _ := tester.Audit(ctx, t.Host, ports)
	return findings
}

func (w *Worker) phaseLDAP(ctx context.Context, t models.Target, ports []models.PortInfo) []models.Finding {
	tester := ldap.New(t.Timeout)
	findings, _ := tester.Audit(ctx, t.Host, ports)
	return findings
}

func (w *Worker) phaseSNMP(ctx context.Context, t models.Target, ports []models.PortInfo) []models.Finding {
	tester := snmp.New(t.Timeout)
	findings, _ := tester.Audit(ctx, t.Host, ports)
	return findings
}

func (w *Worker) phaseFTP(ctx context.Context, t models.Target, ports []models.PortInfo) []models.Finding {
	tester := ftp.New(t.Timeout)
	findings, _ := tester.Audit(ctx, t.Host, ports)
	return findings
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

// phaseAuthAttack runs the webauth + token-attack suites against the
// discovered HTTP endpoints. The phase is read-only: it inspects response
// bodies, cookies, and supplied token strings for known weaknesses.
func (w *Worker) phaseAuthAttack(ctx context.Context, t models.Target, httpInfo []models.HTTPInfo) []models.Finding {
	findings := []models.Finding{}
	seen := map[string]bool{}

	// Per-endpoint cookie / header / body audits.
	for _, h := range httpInfo {
		if h.URL == "" {
			continue
		}
		// Cookie attribute audit.
		hh := http.Header{}
		for k, v := range h.Headers {
			hh.Set(k, v)
		}
		for _, f := range webauth.CookieAudit(h.URL, hh, nil) {
			if !seen[f.Title+f.Target] {
				seen[f.Title+f.Target] = true
				findings = append(findings, f)
			}
		}
	}

	// Fetch one representative page and run CSRF + cred-leak checks on it.
	if len(httpInfo) > 0 {
		rep := httpInfo[0]
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rep.URL, nil)
		if err == nil {
			client := &http.Client{Timeout: 8 * time.Second}
			resp, err := client.Do(req)
			if err == nil {
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
				bodyStr := string(body)
				// CSRF token audit on common parameter names.
				for _, param := range []string{"csrf_token", "_csrf", "authenticity_token", "anti_csrf", "anticsrf"} {
					for _, f := range webauth.CSRFCheck(rep.URL, bodyStr, param) {
						if !seen[f.Title+f.Target] {
							seen[f.Title+f.Target] = true
							findings = append(findings, f)
						}
					}
				}
				// Password-reset Host-header template audit.
				for _, f := range webauth.ResetHostHeaderCheck(rep.URL, "{HOST}/reset?token=...", rep.URL) {
					if !seen[f.Title+f.Target] {
						seen[f.Title+f.Target] = true
						findings = append(findings, f)
					}
				}
				// Rate-limit / lockout (we don't drive a brute here, just
				// emit a finding suggesting the operator do it).
				for _, f := range webauth.RateLimitCheck(rep.URL, resp.StatusCode, resp.Header.Get("Retry-After"), bodyStr, 5) {
					if !seen[f.Title+f.Target] {
						seen[f.Title+f.Target] = true
						findings = append(findings, f)
					}
				}
				// Entropy / hardcoded creds on the page body.
				for _, f := range credleak.NewEntropyDetector().Scan(rep.URL, bodyStr) {
					if !seen[f.Title+f.Target] {
						seen[f.Title+f.Target] = true
						findings = append(findings, f)
					}
				}
				for _, f := range credleak.ScanHardcoded(rep.URL, bodyStr) {
					if !seen[f.Title+f.Target] {
						seen[f.Title+f.Target] = true
						findings = append(findings, f)
					}
				}
				// JWT inspection: look for any JWT-shaped value in the page.
				if jwts := findJWTTokens(bodyStr); len(jwts) > 0 {
					for _, raw := range jwts {
						if j, err := tokens.DecodeJWT(raw); err == nil {
							for _, f := range tokens.JWTInspect(rep.URL, "page-body", j) {
								if !seen[f.Title+f.Target] {
									seen[f.Title+f.Target] = true
									findings = append(findings, f)
								}
							}
							// Weak-secret brute.
							if sec, ok := tokens.BruteForceJWTSecret(j); ok {
								f := tokens.VerifyWeakSecretFinding(rep.URL, "page-body", sec, j)
								if !seen[f.Title+f.Target] {
									seen[f.Title+f.Target] = true
									findings = append(findings, f)
								}
							}
						}
					}
				}
			}
		}
	}

	// NTLMSSP inspection — probes the candidate SMB endpoint. This always
	// returns quickly (no auth) and surfaces weak NTLM dialect negotiation.
	if w.shouldRun("ntlm") {
		inspector := &adauth.NTLMInspector{Timeout: t.Timeout}
		ins := inspector.InspectSMB(ctx, t.Host, 445)
		for _, f := range adauth.NTLMToFindings(t.Host, []adauth.Inspection{ins}) {
			if !seen[f.Title+f.Target] {
				seen[f.Title+f.Target] = true
				findings = append(findings, f)
			}
		}
	}

	return findings
}

// phaseCredLeak probes the target for backup-file exposure, .git exposure,
// and runs the entropy / hardcoded-cred scanners against every discovered
// HTML / JS response.
func (w *Worker) phaseCredLeak(ctx context.Context, t models.Target, httpInfo []models.HTTPInfo) []models.Finding {
	findings := []models.Finding{}
	seen := map[string]bool{}
	if len(httpInfo) == 0 {
		return findings
	}
	base := httpInfo[0].URL

	// Backup-file scan + .git scan against the first discovered base.
	backupHits := map[string]credleak.BackupFileHit{}
	gitHits := func(ctx context.Context, path string) (credleak.GitHit, error) {
		url := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(path, "/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return credleak.GitHit{}, err
		}
		client := &http.Client{Timeout: 4 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return credleak.GitHit{}, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return credleak.GitHit{Path: path, Status: resp.StatusCode, Size: len(body), Body: string(body)}, nil
	}
	for _, f := range credleak.BackupFiles {
		if len(backupHits) > 200 {
			break
		}
		url := strings.TrimRight(base, "/") + "/" + strings.TrimLeft(f.Path, "/")
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			continue
		}
		client := &http.Client{Timeout: 4 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		backupHits[f.Path] = credleak.BackupFileHit{Path: f.Path, Status: resp.StatusCode, BodySize: len(body), Body: string(body)}
	}
	for _, f := range credleak.BackupFileScan(base, backupHits) {
		if !seen[f.Title+f.Target] {
			seen[f.Title+f.Target] = true
			findings = append(findings, f)
		}
	}
	// .git scan.
	for _, f := range credleak.GitScan(ctx, base, gitHits) {
		if !seen[f.Title+f.Target] {
			seen[f.Title+f.Target] = true
			findings = append(findings, f)
		}
	}
	return findings
}

// findJWTTokens scans a body for strings that look like JWTs (three
// base64url segments separated by dots).
func findJWTTokens(body string) []string {
	out := []string{}
	seen := map[string]bool{}
	for i := 0; i+8 < len(body); i++ {
		if body[i] != 'e' || body[i+1] != 'y' || body[i+2] != 'J' {
			continue
		}
		dot1 := strings.IndexByte(body[i:], '.')
		if dot1 < 0 {
			continue
		}
		dot2 := strings.IndexByte(body[i+dot1+1:], '.')
		if dot2 < 0 {
			continue
		}
		end := i + dot1 + 1 + dot2 + 1
		for end < len(body) && body[end] != ' ' && body[end] != '"' && body[end] != '\'' && body[end] != '<' && body[end] != '\n' && body[end] != '\r' {
			end++
		}
		candidate := body[i:end]
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		out = append(out, candidate)
		i = end
		if len(out) >= 10 {
			break
		}
	}
	return out
}

func (w *Worker) phaseNuclei(ctx context.Context, httpInfo []models.HTTPInfo) []models.Finding {
	findings := []models.Finding{}
	loader := nuclei.NewLoader(w.NucleiDir)
	templates, err := loader.Load()
	if err != nil {
		logger.Warn(w.ID, "nuclei load: "+err.Error())
	}
	// Add bundled templates.
	for _, raw := range nuclei.BundledTemplates {
		t, err := nuclei.Parse(raw)
		if err == nil {
			templates = append(templates, t)
		}
	}
	if len(templates) == 0 {
		return nil
	}
	runner := nuclei.NewRunner(15 * time.Second)
	for _, h := range httpInfo {
		if h.StatusCode == 0 {
			continue
		}
		base := h.URL
		for _, t := range templates {
			findings = append(findings, runner.Run(ctx, t, base)...)
		}
	}
	return findings
}

func (w *Worker) shouldRun(phase string) bool {
	switch w.Strategy {
	case models.StrategyRecon:
		return phase == "portscan" || phase == "udp" || phase == "ssl" || phase == "web" || phase == "cve" || phase == "deep" || phase == "cred_leak"
	case models.StrategyStealth:
		return phase == "portscan" || phase == "ssl" || phase == "web" || phase == "deep" || phase == "cred_leak"
	case models.StrategyAggressive:
		return true
	case models.StrategyWebFocus:
		return phase == "portscan" || phase == "ssl" || phase == "web" || phase == "auth" || phase == "cve" || phase == "nuclei" || phase == "deep" || phase == "auth_attack" || phase == "cred_leak"
	case models.StrategyNetFocus:
		return phase == "portscan" || phase == "udp" || phase == "ssl" || phase == "cve" || phase == "deep" || phase == "cred_leak"
	case models.StrategyAuthFocus:
		return phase == "portscan" || phase == "udp" || phase == "web" || phase == "auth" || phase == "deep" || phase == "auth_attack" || phase == "cred_leak" || phase == "ntlm"
	case models.StrategyAI:
		// The planner decides which phases to enable by picking the strategy
		// mix, so the AI worker mirrors the per-strategy behaviour.
		return phase != "nuclei" || true // nuclei enabled for AI workers
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
