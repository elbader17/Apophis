// Package tokens implements attacks against bearer-token authentication:
// JWT alg confusion, RS↔HS key confusion, kid path traversal, JWK injection,
// weak-secret brute force; OAuth state validation, redirect_uri bypass; and
// SAML signature-wrapping, comment injection and assertion-replay checks.
//
// All attacks are local: they consume a token the caller already has (or has
// fetched) and produce findings. They do not contact a remote service.
package tokens

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/apophis-eng/apophis/internal/models"
)

// AttackVector identifies the token-attack category.
type AttackVector string

const (
	VectorJWTAlgNone      AttackVector = "jwt-alg-none"
	VectorJWTRSHS         AttackVector = "jwt-rs-hs-confusion"
	VectorJWTKidTraversal AttackVector = "jwt-kid-traversal"
	VectorJWTJWKInjection AttackVector = "jwt-jwk-injection"
	VectorJWTWeakSecret   AttackVector = "jwt-weak-secret"
	VectorOAuthOpenRedir  AttackVector = "oauth-open-redirect"
	VectorOAuthState      AttackVector = "oauth-missing-state"
	VectorSAMLXSW         AttackVector = "saml-xsw"
	VectorSAMLComment     AttackVector = "saml-comment-injection"
	VectorSAMLReplay      AttackVector = "saml-assertion-replay"
)

// F wraps models.Finding with a strongly-typed attack vector.
func F(vector AttackVector, title, target string, sev models.Severity, evidence, desc, exploit, remediation string) models.Finding {
	return models.Finding{
		Title:       title,
		Severity:    sev,
		Category:    "TokenAttack",
		Target:      target,
		Evidence:    evidence,
		Description: desc,
		Exploit:     exploit,
		Remediation: remediation,
		Tags:        []string{"auth-attack", "token-attack", string(vector)},
	}
}

// --- JWT -------------------------------------------------------------------

// JWTHeader is the decoded JWT header.
type JWTHeader struct {
	Alg   string         `json:"alg"`
	Typ   string         `json:"typ"`
	Kid   string         `json:"kid,omitempty"`
	JWK   map[string]any `json:"jwk,omitempty"`
	X5U   string         `json:"x5u,omitempty"`
	Other map[string]any `json:"-"`
}

// JWTPayload is the decoded JWT payload.
type JWTPayload struct {
	Sub   string         `json:"sub,omitempty"`
	Iss   string         `json:"iss,omitempty"`
	Aud   any            `json:"aud,omitempty"`
	Exp   int64          `json:"exp,omitempty"`
	Nbf   int64          `json:"nbf,omitempty"`
	Iat   int64          `json:"iat,omitempty"`
	Jti   string         `json:"jti,omitempty"`
	Other map[string]any `json:"-"`
}

// JWT is a decoded JWT.
type JWT struct {
	Raw       string
	Header    JWTHeader
	Payload   JWTPayload
	Signature []byte
}

// DecodeJWT parses a JWT string into its parts. Errors out if the structure
// is malformed; returns the parts even when the signature doesn't verify.
func DecodeJWT(s string) (*JWT, error) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("jwt must have 3 segments, got %d", len(parts))
	}
	hdrBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("header b64: %w", err)
	}
	payBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("payload b64: %w", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("signature b64: %w", err)
	}
	hdr := JWTHeader{}
	if err := json.Unmarshal(hdrBytes, &hdr); err != nil {
		return nil, fmt.Errorf("header json: %w", err)
	}
	if len(hdrBytes) > 0 {
		_ = json.Unmarshal(hdrBytes, &hdr.Other)
	}
	pay := JWTPayload{}
	if err := json.Unmarshal(payBytes, &pay); err != nil {
		return nil, fmt.Errorf("payload json: %w", err)
	}
	if len(payBytes) > 0 {
		_ = json.Unmarshal(payBytes, &pay.Other)
	}
	return &JWT{Raw: s, Header: hdr, Payload: pay, Signature: sig}, nil
}

// JWTInspect runs every cheap, signature-less check against a parsed JWT and
// returns findings.
func JWTInspect(target, name string, j *JWT) []models.Finding {
	findings := []models.Finding{}
	if j == nil {
		return findings
	}
	// alg=none — signature is empty AND alg explicitly says none.
	if strings.EqualFold(j.Header.Alg, "none") {
		findings = append(findings, F(
			VectorJWTAlgNone,
			fmt.Sprintf("JWT alg=none accepted on %s (%s)", target, name),
			target,
			models.SeverityCritical,
			fmt.Sprintf("alg=%q signature=%d bytes", j.Header.Alg, len(j.Signature)),
			"The server accepts JWTs with alg=none and no signature. Anyone can mint a valid token by base64-encoding a forged payload and stripping the signature.",
			"echo -n '<payload>' | base64 | tr -d '=' | tr '+/' '-_' > payload.b64 && curl -H 'Authorization: Bearer <header>.<payload>.' <API>",
			"Reject alg=none in the verifier. Pin the expected algorithm list in code; never honour 'alg' from the incoming token.",
		))
	}
	// HS256 but a JWK is embedded — RS→HS confusion vector.
	if strings.HasPrefix(strings.ToUpper(j.Header.Alg), "RS") && j.Header.JWK != nil {
		findings = append(findings, F(
			VectorJWTRSHS,
			fmt.Sprintf("JWT RS→HS confusion surface on %s (%s)", target, name),
			target,
			models.SeverityHigh,
			fmt.Sprintf("alg=%s jwk_present=true", j.Header.Alg),
			"The token header embeds a JWK. Servers that 'verify with the key in the header' instead of a pinned public key are vulnerable to RS↔HS confusion: an attacker substitutes the public key as the HMAC secret, signs a forged token with HS256, and the server validates it.",
			"jwt_tool.py <TOKEN> -X k -pk public.pem  # or jwt_tool.py -X h -pk public.pem",
			"Pin the verification key in code (or fetch it from a trusted source keyed on 'kid'). Never use a JWK embedded in the token for verification.",
		))
	}
	// kid path traversal — kid is interpreted as a file path or SQL column.
	if j.Header.Kid != "" && (strings.Contains(j.Header.Kid, "..") ||
		strings.Contains(j.Header.Kid, "/") ||
		strings.Contains(j.Header.Kid, "\\") ||
		strings.HasPrefix(j.Header.Kid, "|") ||
		strings.Contains(j.Header.Kid, "UNION")) {
		findings = append(findings, F(
			VectorJWTKidTraversal,
			fmt.Sprintf("JWT kid header traversal on %s (%s)", target, name),
			target,
			models.SeverityHigh,
			fmt.Sprintf("kid=%q", j.Header.Kid),
			"The server interprets 'kid' as a filesystem path, SQL column, or command argument. An attacker that controls 'kid' can make the verifier load a known key (e.g. /dev/null, the public key file itself) or pull a key from SQL.",
			"jwt_tool.py <TOKEN> -X k -pk public.pem",
			"Treat 'kid' as an opaque identifier looked up in a static table. Reject path separators and SQL metacharacters.",
		))
	}
	// jwk injection — header carries a full key, no pinned verification.
	if j.Header.JWK != nil && strings.HasPrefix(strings.ToUpper(j.Header.Alg), "HS") {
		// Same as the RS case above but for the opposite direction.
		findings = append(findings, F(
			VectorJWTJWKInjection,
			fmt.Sprintf("JWT JWK injection on %s (%s)", target, name),
			target,
			models.SeverityHigh,
			fmt.Sprintf("alg=%s jwk_present=true", j.Header.Alg),
			"Token header embeds the verification key. The server signs tokens with whatever JWK arrives in the header — an attacker submits their own JWK and the server verifies with it.",
			"jwt_tool.py <TOKEN> -X k",
			"Pin the verification key server-side; ignore any JWK in the incoming header.",
		))
	}
	// x5u / x5c — these point to a URL or cert chain that the server may
	// fetch and use as the verification key.
	if j.Header.X5U != "" {
		findings = append(findings, F(
			VectorJWTJWKInjection,
			fmt.Sprintf("JWT x5u URL on %s (%s)", target, name),
			target,
			models.SeverityMedium,
			fmt.Sprintf("x5u=%q", j.Header.X5U),
			"The server fetches and uses the URL in the x5u header as the verification key. An attacker that controls that URL controls verification.",
			"Stand up a server returning your own public key as a PEM and submit a token signed with it.",
			"Don't fetch verification keys from arbitrary URLs. Use a pinned key or a JWKS endpoint you control with strict URL validation.",
		))
	}
	// Expiry / NotBefore in the past.
	if j.Payload.Exp > 0 && j.Payload.Exp < -1 {
		findings = append(findings, F(
			VectorJWTJWKInjection,
			fmt.Sprintf("JWT exp in the past on %s (%s)", target, name),
			target,
			models.SeverityInfo,
			fmt.Sprintf("exp=%d (now=...)", j.Payload.Exp),
			"The token's 'exp' is in the past. If the server does not enforce exp, attacker can replay indefinitely.",
			"Capture a token, wait for natural expiry, replay. If it still works, the verifier is broken.",
			"Verify exp, iat, nbf in the verifier with a small (≤60s) clock skew tolerance.",
		))
	}
	return findings
}

// --- JWT weak-secret brute ------------------------------------------------

// WeakSecrets is the bundled top-1000 HMAC secrets used for JWT brute.
// Loaded from weak_secrets.go (kept separate for size).
var WeakSecrets []string

// BruteForceJWTSecret tries every secret in WeakSecrets against a parsed
// JWT and returns the first secret that matches the signature. The JWT must
// use an HMAC algorithm (HS256 / HS384 / HS512).
func BruteForceJWTSecret(j *JWT) (string, bool) {
	if j == nil {
		return "", false
	}
	alg := strings.ToUpper(j.Header.Alg)
	if !strings.HasPrefix(alg, "HS") {
		return "", false
	}
	// The signing input is header.payload (no signature).
	parts := strings.Split(j.Raw, ".")
	if len(parts) != 3 {
		return "", false
	}
	signing := parts[0] + "." + parts[1]
	for _, sec := range WeakSecrets {
		ok, _ := verifyHMAC(alg, signing, sec, j.Signature)
		if ok {
			return sec, true
		}
	}
	return "", false
}

// VerifyWeakSecretFinding produces the "weak JWT secret" finding.
func VerifyWeakSecretFinding(target, name, secret string, j *JWT) models.Finding {
	return F(
		VectorJWTWeakSecret,
		fmt.Sprintf("JWT signed with weak HMAC secret on %s (%s)", target, name),
		target,
		models.SeverityCritical,
		fmt.Sprintf("alg=%s secret=%q (in bundled top-%d wordlist)", j.Header.Alg, secret, len(WeakSecrets)),
		"The JWT is signed with an HMAC secret that appears in a public wordlist of weak secrets. Anyone with the token (or who knows the issuer) can mint tokens for any user.",
		"Use the recovered secret to mint a forged token: jwt_tool.py <ORIGINAL_TOKEN> -S hs256 -p '<secret>' -d '{\"sub\":\"admin\"}'",
		"Use a 32+ byte random secret from a CSPRNG (e.g. `openssl rand -base64 48`). Reject any token signed with a secret that fails a minimum-entropy check.",
	)
}
