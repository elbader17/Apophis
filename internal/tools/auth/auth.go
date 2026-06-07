package auth

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

type AuthTester struct {
	client *http.Client
}

var defaultCreds = []struct {
	Service string
	Path    string
	User    string
	Pass    string
}{
	{"tomcat-manager", "/manager/html", "tomcat", "tomcat"},
	{"tomcat-manager", "/manager/html", "admin", "admin"},
	{"jenkins", "/login", "admin", "admin"},
	{"jenkins", "/login", "jenkins", "jenkins"},
	{"wordpress", "/wp-login.php", "admin", "admin"},
	{"wordpress", "/wp-login.php", "admin", "password"},
	{"router-generic", "/", "admin", "admin"},
	{"router-generic", "/", "admin", "password"},
	{"router-generic", "/", "root", "root"},
	{"router-generic", "/", "user", "user"},
	{"iis", "/", "administrator", "admin"},
	{"phpmyadmin", "/", "root", ""},
	{"phpmyadmin", "/", "root", "root"},
	{"phpmyadmin", "/", "admin", "admin"},
	{"grafana", "/login", "admin", "admin"},
	{"kibana", "/login", "elastic", "changeme"},
	{"elastic", "/", "elastic", "changeme"},
}

func NewAuthTester(timeout time.Duration) *AuthTester {
	return &AuthTester{
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (a *AuthTester) TestDefaultCredentials(ctx context.Context, baseURL string) []models.Finding {
	findings := []models.Finding{}
	loginPaths := []string{"/", "/login", "/admin", "/admin/login", "/wp-login.php", "/user/login"}
	checked := map[string]bool{}
	for _, path := range loginPaths {
		if checked[path] {
			continue
		}
		checked[path] = true
		target := strings.TrimRight(baseURL, "/") + path
		for _, cred := range defaultCreds {
			select {
			case <-ctx.Done():
				return findings
			default:
			}
			if !pathMatchesService(path, cred.Service) {
				continue
			}
			if ok := a.tryLogin(ctx, target, cred.User, cred.Pass); ok {
				findings = append(findings, models.Finding{
					Title:       fmt.Sprintf("Default credentials accepted: %s/%s at %s", cred.User, cred.Pass, target),
					Severity:    models.SeverityCritical,
					Category:    "Authentication",
					Target:      target,
					Evidence:    fmt.Sprintf("HTTP 200/302 after POST with %s:%s", cred.User, cred.Pass),
					Description: fmt.Sprintf("The endpoint %s accepted default credentials %s/%s. This is a critical misconfiguration.", target, cred.User, cred.Pass),
					Exploit:     fmt.Sprintf("curl -X POST -d 'username=%s&password=%s' %s", cred.User, cred.Pass, target),
					Remediation: "Change default credentials immediately. Enforce strong password policy. Disable default accounts.",
					References:  []string{"https://owasp.org/www-community/vulnerabilities/Use_of_hard-coded_credentials"},
				})
			}
		}
	}
	return findings
}

func pathMatchesService(path, service string) bool {
	switch service {
	case "wordpress":
		return strings.Contains(path, "wp-login")
	case "tomcat-manager":
		return strings.Contains(path, "manager")
	case "jenkins":
		return strings.Contains(path, "login")
	case "phpmyadmin":
		return path == "/" || path == "/index.php" || strings.Contains(path, "phpmyadmin")
	case "grafana":
		return strings.Contains(path, "login")
	case "kibana":
		return strings.Contains(path, "login")
	case "elastic":
		return path == "/"
	}
	return true
}

func (a *AuthTester) tryLogin(ctx context.Context, url, user, pass string) bool {
	form := fmt.Sprintf("username=%s&password=%s", user, pass)

	getReq, _ := http.NewRequestWithContext(ctx, "GET", url, nil)
	getReq.Header.Set("User-Agent", "Apophis/0.1")
	getResp, err := a.client.Do(getReq)
	baseline := []byte{}
	baselineStatus := 0
	baselineLen := -1
	if err == nil {
		baseline, _ = io.ReadAll(io.LimitReader(getResp.Body, 16384))
		getResp.Body.Close()
		baselineStatus = getResp.StatusCode
		baselineLen = len(baseline)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(form))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "Apophis/0.1")
	resp, err := a.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))

	if resp.StatusCode == 302 || resp.StatusCode == 303 {
		return true
	}

	for _, cookie := range resp.Cookies() {
		lower := strings.ToLower(cookie.Name)
		if strings.Contains(lower, "session") || strings.Contains(lower, "sid") || strings.Contains(lower, "auth") || strings.Contains(lower, "token") {
			return true
		}
	}

	bs := strings.ToLower(string(body))
	rejectMarkers := []string{
		"invalid", "incorrect", "failed", "wrong", "denied", "error", "bad credentials", "unauthorized",
		"try again", "not authorized",
	}
	for _, m := range rejectMarkers {
		if strings.Contains(bs, m) {
			return false
		}
	}

	loginMarkers := []string{"logout", "dashboard", "welcome", "signed in", "logged in", "profile", "account"}
	for _, m := range loginMarkers {
		if strings.Contains(bs, m) {
			return true
		}
	}

	if baselineStatus == resp.StatusCode {
		bl := len(body)
		if baselineLen > 0 && bl > 0 && absInt(bl-baselineLen) < 50 {
			return false
		}
	}

	return resp.StatusCode == 200 && resp.StatusCode != baselineStatus
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

func (a *AuthTester) DetectAuthPages(baseURL string) []string {
	candidates := []string{
		"/admin", "/login", "/admin.php", "/wp-login.php",
		"/user/login", "/administrator", "/auth", "/signin",
		"/api/login", "/api/auth", "/management", "/console",
		"/manager", "/actuator", "/.env", "/phpinfo.php",
	}
	found := []string{}
	client := &http.Client{Timeout: 5 * time.Second}
	for _, p := range candidates {
		req, _ := http.NewRequest("GET", strings.TrimRight(baseURL, "/")+p, nil)
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode != 404 {
			found = append(found, p)
		}
	}
	return found
}
