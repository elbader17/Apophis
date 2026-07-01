package credleak

import (
	"fmt"
	"regexp"

	"github.com/apophis-eng/apophis/internal/models"
)

// HardcodedCredPattern matches a single credential-style value with an
// explicit prefix. Each entry has a regex (without the prefix literal —
// caller prepends), a category tag, and the canonical prefix string.
type HardcodedCredPattern struct {
	Name     string
	Prefix   string
	Pattern  *regexp.Regexp
	Severity models.Severity
}

// HardcodedCredPatterns is the bundled catalog of well-known credential
// prefixes (AWS, GCP, GitHub, Stripe, Slack, JWT secrets, etc.).
var HardcodedCredPatterns = []HardcodedCredPattern{
	{
		Name:     "AWS Access Key ID",
		Prefix:   "AKIA",
		Pattern:  regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "AWS Secret Access Key",
		Prefix:   "aws_secret_access_key",
		Pattern:  regexp.MustCompile(`(?i)aws[_-]?secret[_-]?access[_-]?key["'\s:=]+([A-Za-z0-9/+=]{40})`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "GCP API key",
		Prefix:   "AIza",
		Pattern:  regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
		Severity: models.SeverityHigh,
	},
	{
		Name:     "GitHub personal access token",
		Prefix:   "ghp_",
		Pattern:  regexp.MustCompile(`ghp_[A-Za-z0-9]{36,255}`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "GitHub OAuth token",
		Prefix:   "gho_",
		Pattern:  regexp.MustCompile(`gho_[A-Za-z0-9]{36,255}`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "GitHub user-to-server token",
		Prefix:   "ghu_",
		Pattern:  regexp.MustCompile(`ghu_[A-Za-z0-9]{36,255}`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "GitHub server-to-server token",
		Prefix:   "ghs_",
		Pattern:  regexp.MustCompile(`ghs_[A-Za-z0-9]{36,255}`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "GitHub refresh token",
		Prefix:   "ghr_",
		Pattern:  regexp.MustCompile(`ghr_[A-Za-z0-9]{36,255}`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "Slack API token",
		Prefix:   "xox",
		Pattern:  regexp.MustCompile(`xox[baprs]-[A-Za-z0-9-]{10,48}`),
		Severity: models.SeverityHigh,
	},
	{
		Name:     "Stripe live secret key",
		Prefix:   "sk_live_",
		Pattern:  regexp.MustCompile(`sk_live_[A-Za-z0-9]{24,255}`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "Stripe test secret key",
		Prefix:   "sk_test_",
		Pattern:  regexp.MustCompile(`sk_test_[A-Za-z0-9]{24,255}`),
		Severity: models.SeverityMedium,
	},
	{
		Name:     "Stripe live restricted key",
		Prefix:   "rk_live_",
		Pattern:  regexp.MustCompile(`rk_live_[A-Za-z0-9]{24,255}`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "Google OAuth refresh token",
		Prefix:   "1//",
		Pattern:  regexp.MustCompile(`1//[0-9A-Za-z\-_]{43,255}`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "Bearer token (long)",
		Prefix:   "Bearer",
		Pattern:  regexp.MustCompile(`(?i)Bearer\s+([A-Za-z0-9\-_\.=]{40,})`),
		Severity: models.SeverityHigh,
	},
	{
		Name:     "JWT in source",
		Prefix:   "eyJ",
		Pattern:  regexp.MustCompile(`eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}`),
		Severity: models.SeverityMedium,
	},
	{
		Name:     "Heroku API key",
		Prefix:   "heroku",
		Pattern:  regexp.MustCompile(`(?i)heroku[_-]?api[_-]?key["'\s:=]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`),
		Severity: models.SeverityHigh,
	},
	{
		Name:     "Mailgun API key",
		Prefix:   "key-",
		Pattern:  regexp.MustCompile(`key-[0-9a-zA-Z]{32}`),
		Severity: models.SeverityHigh,
	},
	{
		Name:     "Twilio Account SID",
		Prefix:   "AC",
		Pattern:  regexp.MustCompile(`AC[0-9a-f]{32}`),
		Severity: models.SeverityHigh,
	},
	{
		Name:     "Twilio Auth Token",
		Prefix:   "twilio",
		Pattern:  regexp.MustCompile(`(?i)twilio[_-]?auth[_-]?token["'\s:=]+([0-9a-f]{32})`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "SendGrid API key",
		Prefix:   "SG.",
		Pattern:  regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "OpenAI API key",
		Prefix:   "sk-",
		Pattern:  regexp.MustCompile(`sk-[A-Za-z0-9]{20,255}T3BlbkFJ[A-Za-z0-9]{20,255}`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "Anthropic API key",
		Prefix:   "sk-ant",
		Pattern:  regexp.MustCompile(`sk-ant-[A-Za-z0-9_\-]{32,255}`),
		Severity: models.SeverityHigh,
	},
	{
		Name:     "npm token",
		Prefix:   "npm_",
		Pattern:  regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		Severity: models.SeverityHigh,
	},
	{
		Name:     "PyPI token",
		Prefix:   "pypi",
		Pattern:  regexp.MustCompile(`pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}`),
		Severity: models.SeverityHigh,
	},
	{
		Name:     "Private key (PEM)",
		Prefix:   "-----BEGIN",
		Pattern:  regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`),
		Severity: models.SeverityCritical,
	},
	{
		Name:     "RSA / SSH key marker",
		Prefix:   "ssh-rsa",
		Pattern:  regexp.MustCompile(`ssh-(?:rsa|dss|ed25519|ecdsa) AAAA[0-9A-Za-z+/=]{40,}`),
		Severity: models.SeverityHigh,
	},
}

// Scan returns findings for every hardcoded-credential pattern that
// matched the supplied body (typically the contents of a JS bundle or an
// .env dump).
func ScanHardcoded(target, body string) []models.Finding {
	if body == "" {
		return nil
	}
	findings := []models.Finding{}
	seen := map[string]bool{}
	for _, p := range HardcodedCredPatterns {
		if m := p.Pattern.FindString(body); m != "" {
			if seen[p.Name] {
				continue
			}
			seen[p.Name] = true
			findings = append(findings, F(
				VectorHardcodedCreds,
				fmt.Sprintf("Hardcoded %s in HTTP response on %s", p.Name, target),
				target,
				p.Severity,
				fmt.Sprintf("pattern=%s match_preview=%q", p.Name, preview(m)),
				fmt.Sprintf("The HTTP response contains a hardcoded %s. The token is exposed to anyone who can fetch the URL — including anonymous users, search engine caches, and Wayback Machine archives.", p.Name),
				"curl the URL, extract the token, and use it directly. Most providers' tokens are usable from any IP until rotated.",
				"Move all credentials out of client-side bundles and public responses. Use a runtime secret manager. Rotate any token that has been committed to a public bundle.",
			))
		}
	}
	return findings
}
