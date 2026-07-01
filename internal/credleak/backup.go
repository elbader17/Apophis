package credleak

import (
	"context"
	"fmt"
	"strings"

	"github.com/apophis-eng/apophis/internal/models"
)

// BackupFile is a candidate backup / sensitive file that we test for.
type BackupFile struct {
	Path     string
	Severity models.Severity
	Reason   string
}

// BackupFiles is the bundled catalog of common backup / sensitive files
// exposed by web applications. The list is intentionally short — these are
// the hits we've seen most often in audits.
var BackupFiles = []BackupFile{
	{Path: ".git/HEAD", Severity: models.SeverityCritical, Reason: "git HEAD — full repository likely exposed"},
	{Path: ".git/config", Severity: models.SeverityCritical, Reason: "git config — may contain remote URLs and credentials"},
	{Path: ".git/index", Severity: models.SeverityCritical, Reason: "git index — pack of source code"},
	{Path: ".env", Severity: models.SeverityCritical, Reason: "environment file — secrets, DB credentials"},
	{Path: ".env.local", Severity: models.SeverityCritical, Reason: "local env — secrets"},
	{Path: ".env.production", Severity: models.SeverityCritical, Reason: "production env — secrets"},
	{Path: ".env.development", Severity: models.SeverityHigh, Reason: "development env — may contain test credentials"},
	{Path: ".aws/credentials", Severity: models.SeverityCritical, Reason: "AWS CLI credentials"},
	{Path: ".ssh/id_rsa", Severity: models.SeverityCritical, Reason: "SSH private key"},
	{Path: ".ssh/id_ed25519", Severity: models.SeverityCritical, Reason: "SSH private key"},
	{Path: ".ssh/id_dsa", Severity: models.SeverityCritical, Reason: "SSH private key (legacy)"},
	{Path: ".ssh/authorized_keys", Severity: models.SeverityMedium, Reason: "SSH authorized keys"},
	{Path: ".ssh/config", Severity: models.SeverityMedium, Reason: "SSH config — may contain proxy jump info"},
	{Path: ".pgpass", Severity: models.SeverityCritical, Reason: "PostgreSQL password file"},
	{Path: ".my.cnf", Severity: models.SeverityHigh, Reason: "MySQL config — may contain credentials"},
	{Path: ".netrc", Severity: models.SeverityHigh, Reason: "netrc — credentials for FTP / curl / git"},
	{Path: ".npmrc", Severity: models.SeverityHigh, Reason: "npm config — may contain auth tokens"},
	{Path: ".pypirc", Severity: models.SeverityHigh, Reason: "PyPI config — may contain credentials"},
	{Path: ".git-credentials", Severity: models.SeverityCritical, Reason: "git credential helper store — plaintext"},
	{Path: ".htpasswd", Severity: models.SeverityHigh, Reason: "Apache htpasswd — hashed passwords"},
	{Path: ".docker/config.json", Severity: models.SeverityHigh, Reason: "Docker config — may contain registry creds"},
	{Path: ".bash_history", Severity: models.SeverityMedium, Reason: "shell history — may contain typed secrets"},
	{Path: ".zsh_history", Severity: models.SeverityMedium, Reason: "shell history"},
	{Path: ".python_history", Severity: models.SeverityLow, Reason: "Python REPL history"},
	{Path: ".psql_history", Severity: models.SeverityMedium, Reason: "psql history — may contain queries with embedded credentials"},
	{Path: ".mysql_history", Severity: models.SeverityMedium, Reason: "mysql history"},
	{Path: ".rediscli_history", Severity: models.SeverityLow, Reason: "redis-cli history"},
	{Path: ".mongosh_history", Severity: models.SeverityLow, Reason: "mongosh history"},
	{Path: ".dbeaver-data-sources.xml", Severity: models.SeverityHigh, Reason: "DBeaver data sources — plaintext DB creds"},
	{Path: "id_rsa", Severity: models.SeverityCritical, Reason: "SSH private key (root of user)"},
	{Path: "id_dsa", Severity: models.SeverityCritical, Reason: "SSH private key (legacy)"},
	{Path: "backup.sql", Severity: models.SeverityHigh, Reason: "SQL dump — may contain PII / hashes"},
	{Path: "dump.sql", Severity: models.SeverityHigh, Reason: "SQL dump"},
	{Path: "database.sql", Severity: models.SeverityHigh, Reason: "SQL dump"},
	{Path: "backup.tar.gz", Severity: models.SeverityMedium, Reason: "compressed backup"},
	{Path: "backup.zip", Severity: models.SeverityMedium, Reason: "compressed backup"},
	{Path: "wp-config.php.bak", Severity: models.SeverityCritical, Reason: "WordPress config backup"},
	{Path: "wp-config.php~", Severity: models.SeverityCritical, Reason: "WordPress config editor backup"},
	{Path: "configuration.php.bak", Severity: models.SeverityHigh, Reason: "Joomla config backup"},
	{Path: ".htaccess.bak", Severity: models.SeverityLow, Reason: "Apache config backup"},
	{Path: "web.config.bak", Severity: models.SeverityLow, Reason: "IIS config backup"},
	{Path: "server.cfg", Severity: models.SeverityLow, Reason: "server config"},
	{Path: "swagger.json", Severity: models.SeverityInfo, Reason: "OpenAPI / Swagger spec"},
	{Path: "swagger.yaml", Severity: models.SeverityInfo, Reason: "OpenAPI / Swagger spec"},
	{Path: "openapi.json", Severity: models.SeverityInfo, Reason: "OpenAPI spec"},
	{Path: "openapi.yaml", Severity: models.SeverityInfo, Reason: "OpenAPI spec"},
	{Path: "api-docs", Severity: models.SeverityInfo, Reason: "API docs"},
	{Path: "phpinfo.php", Severity: models.SeverityMedium, Reason: "PHP info — full server configuration"},
	{Path: "info.php", Severity: models.SeverityMedium, Reason: "PHP info"},
	{Path: "test.php", Severity: models.SeverityLow, Reason: "PHP test page"},
	{Path: "debug.log", Severity: models.SeverityMedium, Reason: "application debug log"},
	{Path: "error.log", Severity: models.SeverityMedium, Reason: "application error log"},
	{Path: "trace.log", Severity: models.SeverityMedium, Reason: "application trace log"},
	{Path: "access.log", Severity: models.SeverityMedium, Reason: "web access log — may contain session tokens"},
}

// BackupFileScan takes a map of path → http-status + body-size and reports
// findings for any path that returned a non-empty body.
func BackupFileScan(target string, results map[string]BackupFileHit) []models.Finding {
	findings := []models.Finding{}
	for _, f := range BackupFiles {
		hit, ok := results[f.Path]
		if !ok || hit.Status < 200 || hit.Status >= 400 {
			continue
		}
		if hit.BodySize == 0 {
			continue
		}
		findings = append(findings, F(
			VectorBackupFile,
			fmt.Sprintf("Sensitive file exposed on %s (%s)", target, f.Path),
			target,
			f.Severity,
			fmt.Sprintf("path=%s status=%d size=%d", f.Path, hit.Status, hit.BodySize),
			fmt.Sprintf("A sensitive file is web-accessible: %s. %s", f.Path, f.Reason),
			strings.TrimSpace(fmt.Sprintf("curl -s https://%s/%s | head -100", target, f.Path)),
			fmt.Sprintf("Block public access to %s in the web server config. Audit git history for any credentials that were committed in this file.", f.Path),
		))
	}
	return findings
}

// BackupFileHit is the input to BackupFileScan.
type BackupFileHit struct {
	Path     string
	Status   int
	BodySize int
	Body     string
}

// FetchAllBackupFiles is a convenience helper that takes a base URL and an
// HTTP fetcher, and returns the hits as a map. The fetcher is provided by
// the caller so the credleak package doesn't depend on a specific HTTP
// implementation.
type BackupFileFetcher func(ctx Context, path string) (BackupFileHit, error)

// Context is just an alias for context.Context (re-exported here so the
// public API doesn't need to import "context").
type Context = context.Context

// FetchAndScan walks the BackupFiles list using the supplied fetcher and
// returns findings for any hit.
func FetchAndScan(ctx Context, base string, fetch BackupFileFetcher) []models.Finding {
	if fetch == nil {
		return nil
	}
	results := map[string]BackupFileHit{}
	for _, f := range BackupFiles {
		hit, err := fetch(ctx, f.Path)
		if err != nil {
			continue
		}
		results[f.Path] = hit
	}
	return BackupFileScan(base, results)
}
