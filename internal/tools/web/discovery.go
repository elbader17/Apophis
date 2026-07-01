package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/apophis-eng/apophis/internal/models"
)

var pathSignatures = map[string][]string{
	"/.git/HEAD":                {"ref:", "gitdir:"},
	"/.git/config":              {"[core]", "[remote]", "repositoryformatversion"},
	"/.svn/entries":             {"svn:wc:ra_dav_version", "wc-db"},
	"/.env":                     {"DB_PASSWORD", "API_KEY", "SECRET_KEY", "APP_KEY", "AWS_ACCESS", "PRIVATE_KEY"},
	"/.env.local":               {"DB_PASSWORD", "API_KEY", "SECRET_KEY", "APP_KEY", "AWS_ACCESS"},
	"/.env.production":          {"DB_PASSWORD", "API_KEY", "SECRET_KEY", "APP_KEY", "AWS_ACCESS"},
	"/env":                      {"DB_PASSWORD", "API_KEY", "SECRET_KEY"},
	"/config":                   {"\"database\":", "secret_key", "secret_access_key"},
	"/config.php":               {"<?php", "define(", "$config['"},
	"/configuration.php":        {"<?php", "define("},
	"/wp-config.php":            {"<?php", "DB_NAME", "DB_PASSWORD", "DB_USER"},
	"/config/database.yml":      {"database:", "adapter:", "username:", "password:"},
	"/backup.sql":               {"CREATE TABLE", "INSERT INTO", "DROP TABLE"},
	"/dump.sql":                 {"CREATE TABLE", "INSERT INTO"},
	"/db.sqlite":                {"SQLite format"},
	"/db.sqlite3":               {"SQLite format"},
	"/.htpasswd":                {"apr1", "$apr1", "$2y$"},
	"/.aws/credentials":         {"aws_access_key_id", "aws_secret_access_key"},
	"/.ssh/id_rsa":              {"-----BEGIN", "PRIVATE KEY"},
	"/id_rsa":                   {"-----BEGIN", "PRIVATE KEY"},
	"/phpinfo.php":              {"PHP Version", "phpinfo()"},
	"/server-status":            {"Apache Server Status", "Server Version"},
	"/server-info":              {"Apache Server Information", "Server Version"},
	"/actuator":                 {"_links", "actuator"},
	"/actuator/env":             {"propertySources", "activeProfiles"},
	"/actuator/beans":           {"beans", "contexts"},
	"/swagger-ui.html":          {"Swagger UI", "swagger-ui"},
	"/api-docs":                 {"swagger", "openapi"},
	"/graphql":                  {"__schema", "GraphQL"},
	"/.DS_Store":                {"Bud1", "Iloc"},
	"/Dockerfile":               {"FROM ", "RUN ", "CMD "},
	"/docker-compose.yml":       {"version:", "services:"},
	"/package.json":             {"\"dependencies\":", "\"devDependencies\":"},
	"/composer.json":            {"\"require\":", "\"autoload\":"},
	"/robots.txt":               {"User-agent", "Disallow"},
	"/.gitignore":               {"node_modules"},
	"/health":                   {"\"status\""},
	"/healthz":                  {"\"status\""},
	"/version":                  {"\"version\""},
	"/.well-known/security.txt": {"Contact", "Expires"},
}

var commonPaths = []string{
	"/.git/HEAD",
	"/.git/config",
	"/.svn/entries",
	"/.env",
	"/.env.local",
	"/.env.production",
	"/env",
	"/config",
	"/config.php",
	"/configuration.php",
	"/wp-config.php",
	"/config/database.yml",
	"/backup",
	"/backup.sql",
	"/dump.sql",
	"/database.sql",
	"/db.sqlite",
	"/db.sqlite3",
	"/.DS_Store",
	"/.htaccess",
	"/.htpasswd",
	"/server-status",
	"/server-info",
	"/.well-known/security.txt",
	"/phpinfo.php",
	"/info.php",
	"/test.php",
	"/debug",
	"/trace",
	"/actuator",
	"/actuator/env",
	"/actuator/health",
	"/actuator/beans",
	"/actuator/mappings",
	"/swagger",
	"/swagger-ui.html",
	"/api-docs",
	"/api/v1",
	"/api/v2",
	"/graphql",
	"/graphiql",
	"/.aws/credentials",
	"/.ssh/id_rsa",
	"/id_rsa",
	"/docker-compose.yml",
	"/Dockerfile",
	"/package.json",
	"/composer.json",
	"/Gemfile",
	"/requirements.txt",
	"/robots.txt",
	"/sitemap.xml",
	"/crossdomain.xml",
	"/.well-known/openid-configuration",
	"/admin",
	"/administrator",
	"/admin.php",
	"/admin/login",
	"/admin/index.php",
	"/wp-admin",
	"/wp-login.php",
	"/user/login",
	"/login",
	"/signin",
	"/signup",
	"/register",
	"/forgot",
	"/uploads",
	"/upload",
	"/files",
	"/media",
	"/static",
	"/assets",
	"/css",
	"/js",
	"/img",
	"/images",
	"/docs",
	"/doc",
	"/help",
	"/readme",
	"/README",
	"/README.md",
	"/changelog",
	"/CHANGELOG",
	"/license",
	"/LICENSE",
	"/console",
	"/shell",
	"/cmd",
	"/exec",
	"/cgi-bin",
	"/cgi-bin/test",
	"/phpmyadmin",
	"/pma",
	"/adminer",
	"/adminer.php",
	"/manager",
	"/manager/html",
	"/jenkins",
	"/jmx-console",
	"/web-console",
	"/webdav",
	"/.idea",
	"/.vscode",
	"/.editorconfig",
	"/.gitignore",
	"/health",
	"/healthz",
	"/ready",
	"/readyz",
	"/live",
	"/livez",
	"/ping",
	"/version",
	"/status",
	"/metrics",
	"/probe",
	"/info",
	"/whoami",
	"/debug/pprof",
	"/debug/vars",
	"/internal",
	"/private",
	"/secret",
	"/hidden",
	"/backup.zip",
	"/site.zip",
	"/www.zip",
	"/html.zip",
	"/app.zip",
	"/source.zip",
}

type Discovery struct {
	client *http.Client
}

func NewDiscovery(c *http.Client) *Discovery {
	if c == nil {
		c = &http.Client{}
	}
	return &Discovery{client: c}
}

func (d *Discovery) BrutePaths(ctx context.Context, baseURL string) []models.Finding {
	if baseURL == "" {
		return nil
	}
	base := strings.TrimRight(baseURL, "/")
	findings := []models.Finding{}
	seen := map[string]int{}
	for _, p := range commonPaths {
		select {
		case <-ctx.Done():
			return findings
		default:
		}
		u := base + p
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		req.Header.Set("User-Agent", "Apophis/0.1")
		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		if resp.StatusCode == 404 {
			continue
		}
		seen[p] = resp.StatusCode
		bodyStr := string(body)
		if sigs, hasSigs := pathSignatures[p]; hasSigs {
			matched := false
			lower := strings.ToLower(bodyStr)
			for _, sig := range sigs {
				if strings.Contains(lower, strings.ToLower(sig)) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}
		sev, category := classifyPath(p, resp.StatusCode, bodyStr)
		if sev == "" {
			continue
		}
		findings = append(findings, models.Finding{
			Title:       fmt.Sprintf("Exposed path: %s (HTTP %d)", p, resp.StatusCode),
			Severity:    sev,
			Category:    category,
			Target:      u,
			Evidence:    fmt.Sprintf("HTTP %d on %s, body=%d bytes", resp.StatusCode, u, len(body)),
			Description: fmt.Sprintf("Path %s returned HTTP %d. This often indicates exposed configuration, debug endpoints, or admin interfaces.", p, resp.StatusCode),
			Exploit:     fmt.Sprintf("Manual inspection: curl -i %s. Use gobuster/dirsearch for full enumeration.", u),
			Remediation: "Restrict access via ACL, remove debug endpoints in production, configure robots.txt and WAF rules.",
		})
	}
	return findings
}

func classifyPath(path string, status int, body string) (models.Severity, string) {
	critical := []string{"/.env", "/.git/HEAD", "/.git/config", "/.svn/entries", "/.htpasswd", "/id_rsa", "/.aws/credentials", "/config/database.yml", "/.ssh/id_rsa", "/phpinfo.php"}
	high := []string{"/.git", "/.svn", "/backup.sql", "/dump.sql", "/db.sqlite", "/actuator/env", "/actuator/beans", "/adminer.php", "/phpmyadmin", "/pma", "/adminer", "/manager/html", "/jmx-console", "/web-console", "/.htaccess", "/config", "/webdav", "/cgi-bin"}
	medium := []string{"/actuator", "/swagger-ui.html", "/swagger", "/api-docs", "/graphql", "/graphiql", "/wp-config.php", "/admin", "/administrator", "/admin.php", "/admin/login", "/wp-admin", "/wp-login.php", "/admin/index.php", "/server-status", "/server-info", "/jenkins", "/console", "/debug", "/.DS_Store"}

	for _, c := range critical {
		if path == c || strings.HasPrefix(path, c) {
			return models.SeverityCritical, "Information Disclosure"
		}
	}
	for _, c := range high {
		if path == c || strings.HasPrefix(path, c) {
			return models.SeverityHigh, "Information Disclosure"
		}
	}
	for _, c := range medium {
		if path == c || strings.HasPrefix(path, c) {
			return models.SeverityMedium, "Information Disclosure"
		}
	}
	if status == 200 {
		return models.SeverityInfo, "Discovery"
	}
	if status == 401 || status == 403 {
		return models.SeverityLow, "Discovery"
	}
	return "", ""
}
