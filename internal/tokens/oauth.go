package tokens

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/apophis-eng/apophis/internal/models"
)

// OAuthConfig describes the OAuth/OIDC endpoints the auditor is targeting.
type OAuthConfig struct {
	AuthEndpoint string // e.g. https://idp/oauth2/authorize
	RedirectURI  string // the SP's redirect_uri (registered value)
	ClientID     string
	Scopes       []string
	// AllowedRedirects is the set of redirect_uri values the IdP would
	// accept (typically the registered redirect, sometimes with wildcards
	// the IdP strips — provided by the operator).
	AllowedRedirects []string
}

// OAuthInspect checks the OAuth config for common misconfigurations.
func OAuthInspect(target string, cfg OAuthConfig) []models.Finding {
	findings := []models.Finding{}
	// 1. redirect_uri parsing — make sure the configured redirect parses
	//    cleanly. If the operator listed multiple values, check that they
	//    share the same origin.
	if cfg.RedirectURI != "" {
		u, err := url.Parse(cfg.RedirectURI)
		if err != nil {
			findings = append(findings, F(
				VectorOAuthOpenRedir,
				fmt.Sprintf("OAuth redirect_uri malformed on %s (%s)", target, cfg.RedirectURI),
				target,
				models.SeverityHigh,
				"redirect_uri="+cfg.RedirectURI,
				"The configured redirect_uri is not a parseable URL. Many IdPs handle this case by allowing whatever the client sends, which means an attacker can choose.",
				"Submit a phishing flow with redirect_uri=https://attacker.example/callback. The IdP will redirect the code to the attacker.",
				"Validate redirect_uri strictly: must parse, must match the registered value exactly (no wildcards).",
			))
			return findings
		}
		// Wildcard / suffix matches.
		if strings.Contains(cfg.RedirectURI, "*") {
			findings = append(findings, F(
				VectorOAuthOpenRedir,
				fmt.Sprintf("OAuth redirect_uri contains wildcard on %s (%s)", target, cfg.RedirectURI),
				target,
				models.SeverityCritical,
				"redirect_uri="+cfg.RedirectURI,
				"A wildcard in the registered redirect_uri lets an attacker substitute the prefix or suffix. Example: a registered 'https://*.example.com/cb' allows 'https://attacker.example.com/cb'.",
				"Register 'https://*.attacker.example.com/cb' as the redirect and complete the flow; the code is sent to attacker.example.com.",
				"Replace wildcards with explicit enumerations. If you must allow dynamic subdomains, validate them against a strict allow-list.",
			))
		}
		// Subdomain mismatch.
		for _, allowed := range cfg.AllowedRedirects {
			au, _ := url.Parse(allowed)
			if au == nil {
				continue
			}
			if au.Host != "" && u.Host != "" && !sameOrigin(au, u) && !strings.HasSuffix(u.Host, au.Host) {
				findings = append(findings, F(
					VectorOAuthOpenRedir,
					fmt.Sprintf("OAuth redirect_uri origin drift on %s: registered=%s configured=%s", target, allowed, cfg.RedirectURI),
					target,
					models.SeverityMedium,
					fmt.Sprintf("registered=%s configured=%s", allowed, cfg.RedirectURI),
					"The configured redirect_uri has a different origin than the registered value. Some IdPs match loosely and accept either, which broadens the attack surface for an open-redirect.",
					"Submit the configured redirect_uri to the auth endpoint and verify the IdP accepts it; if it does, an attacker who steals the code can redirect to a host they control with a similar origin.",
					"Re-register the redirect_uri explicitly. Disable loose matching on the IdP.",
				))
			}
		}
	}
	// 2. Open redirect in the post-logout / post-redirect target — we don't
	//    have the response to inspect, but if the operator flagged any
	//    post_logout_redirect_uri value, flag it.
	//    (Covered in OpenRedirectCheck below.)
	// 3. State missing — most modern SDKs enforce this; the operator can
	//    confirm via the audit tool.
	return findings
}

// OpenRedirectURLCheck tests whether the supplied final URL is acceptable
// for the OAuth flow's post-auth redirect.
func OpenRedirectURLCheck(target, redirectURL string, allow []string) []models.Finding {
	if redirectURL == "" || len(allow) == 0 {
		return nil
	}
	u, err := url.Parse(redirectURL)
	if err != nil {
		return []models.Finding{F(
			VectorOAuthOpenRedir,
			fmt.Sprintf("OAuth post-auth redirect URL unparseable on %s", target),
			target,
			models.SeverityHigh,
			"redirect="+redirectURL,
			"The supplied redirect URL is not parseable. An attacker controlling this parameter can replace it with a malicious URL.",
			"Substitute the redirect with https://attacker.example/cb and observe the IdP's behaviour.",
			"Strict-validate post-auth / post-logout redirect URLs against an explicit allow-list.",
		)}
	}
	for _, a := range allow {
		if sameHost(u, a) {
			return nil
		}
	}
	return []models.Finding{F(
		VectorOAuthOpenRedir,
		fmt.Sprintf("OAuth post-auth redirect URL not in allow-list on %s", target),
		target,
		models.SeverityHigh,
		fmt.Sprintf("redirect=%s allow=%v", redirectURL, allow),
		"The supplied redirect URL is not on the allow-list. If the IdP honours the client-supplied value, an attacker can exfiltrate the auth code to their own server.",
		"Submit a phishing URL with redirect_uri=https://attacker.example/cb; if the IdP honours it, the code is captured.",
		"Reject any redirect URL not on the explicit allow-list, regardless of host suffix or scheme.",
	)}
}

// OAuthStateCheck looks for the presence of a `state` parameter in the auth
// request URL. If absent, the operator should be alerted.
func OAuthStateCheck(target, authURL string) []models.Finding {
	u, err := url.Parse(authURL)
	if err != nil {
		return nil
	}
	q := u.Query()
	if _, ok := q["state"]; !ok {
		return []models.Finding{F(
			VectorOAuthState,
			fmt.Sprintf("OAuth authorize URL missing state on %s", target),
			target,
			models.SeverityMedium,
			"auth_url="+authURL,
			"The authorize URL does not contain a 'state' parameter. Without state, a CSRF attacker can complete an OAuth flow with the victim's session, binding the attacker's identity to the victim's account.",
			"Submit the authorize URL from a victim's browser; complete the flow with the attacker's credentials; the victim is now logged in as the attacker.",
			"Generate a cryptographically random state value per request; bind it to the user session; verify it on the callback.",
		)}
	}
	if len(q.Get("state")) < 16 {
		return []models.Finding{F(
			VectorOAuthState,
			fmt.Sprintf("OAuth state parameter too short on %s", target),
			target,
			models.SeverityLow,
			fmt.Sprintf("state_len=%d", len(q.Get("state"))),
			"The 'state' parameter is shorter than 16 characters — a brute-force attack against the CSRF state is feasible.",
			"Capture 2^15 authorize requests and brute-force the state.",
			"Use at least 128 bits of entropy (≥22 characters base64) for state.",
		)}
	}
	return nil
}

// sameOrigin reports whether two URLs have the same scheme + host.
func sameOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Scheme == b.Scheme && strings.EqualFold(a.Host, b.Host)
}

func sameHost(u *url.URL, allow string) bool {
	a, err := url.Parse(allow)
	if err != nil {
		return false
	}
	return sameOrigin(u, a)
}
