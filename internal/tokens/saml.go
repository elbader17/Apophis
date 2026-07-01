package tokens

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

// SAMLResponse is the decoded SAML <Response> XML (base64-decoded once).
// We parse just enough XML — namespaces, Assertion blocks, Conditions,
// NotBefore / NotOnOrAfter — to drive the security checks.
type SAMLResponse struct {
	Raw           []byte
	Assertions    []SAMLAssertion
	Issuer        string
	Destination   string
	InResponseTo  string
	HasSignature  bool
	SignatureAlgo string
	HasComments   bool
}

// SAMLAssertion is a single <Assertion> element from a Response.
type SAMLAssertion struct {
	ID           string
	Issuer       string
	Subject      string
	NotBefore    time.Time
	NotOnOrAfter time.Time
	Audience     []string
	HasComments  bool
	HasNameID    bool
}

// ParseSAMLResponse base64-decodes a SAML response and walks it to pull the
// Assertion blocks. We accept either base64-encoded or plain XML.
func ParseSAMLResponse(raw string) (*SAMLResponse, error) {
	// Try base64 first.
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		// Fall back: it's plain XML.
		decoded = []byte(raw)
	}
	out := &SAMLResponse{Raw: decoded}
	x := string(decoded)
	out.HasComments = strings.Contains(x, "<!--")
	out.HasSignature = strings.Contains(x, "<Signature") || strings.Contains(x, "ds:Signature")
	out.Issuer = firstXMLElementContent(x, "Issuer")
	out.Destination = attrValue(x, "Response", "Destination")
	out.InResponseTo = attrValue(x, "Response", "InResponseTo")
	out.SignatureAlgo = firstSignatureAlgo(x)

	// Find every Assertion block (possibly inside an EncryptedAssertion).
	for _, a := range extractAssertions(x) {
		out.Assertions = append(out.Assertions, a)
	}
	return out, nil
}

// SAMLInspect runs every SAML-specific check and returns findings.
func SAMLInspect(target, name string, r *SAMLResponse) []models.Finding {
	if r == nil {
		return nil
	}
	findings := []models.Finding{}
	// Missing signature.
	if !r.HasSignature {
		findings = append(findings, F(
			VectorSAMLXSW,
			fmt.Sprintf("SAML response without <Signature> on %s (%s)", target, name),
			target,
			models.SeverityCritical,
			"signature_present=false",
			"The SAML Response has no <Signature>. Anyone who can inject a forged Response into the ACS URL can authenticate as any user.",
			"Craft a SAML Response with an arbitrary NameID and POST it to the ACS endpoint.",
			"Reject any Response / Assertion that lacks a valid <ds:Signature> referencing a trusted IdP cert. Reject unsigned assertions (xmlsec allow-untrusted-assertions = false).",
		))
	}
	// Comments in signed assertion — comment injection. SAML libraries that
	// strip comments for canonicalization but not for the original signed
	// XML can be tricked into a different payload.
	if r.HasComments {
		findings = append(findings, F(
			VectorSAMLComment,
			fmt.Sprintf("SAML XML comments present in signed assertion on %s (%s)", target, name),
			target,
			models.SeverityHigh,
			"xml_comments_in_response=true",
			"Comments embedded in the signed XML give the attacker room to embed a hidden signed assertion. Some SAML stacks recompute the signature over the comment-stripped canonical form while keeping the original payload, allowing a hidden <Assertion> with arbitrary subject to slip through.",
			"SAML Raider / 'SAML Comment Injection' (Burp extension) crafts an Assertion with a hidden subject inside an XML comment, then signs only the outer Response.",
			"Strip comments before signature validation AND before XML parsing. Reject any SAML payload that contains <!-- ... --> inside <Assertion> or <Response>.",
		))
	}
	// Weak signature algorithm.
	if r.SignatureAlgo != "" && (strings.Contains(r.SignatureAlgo, "sha1") ||
		strings.Contains(r.SignatureAlgo, "rsa-sha1") ||
		strings.Contains(r.SignatureAlgo, "hmac-sha1")) {
		findings = append(findings, F(
			VectorSAMLXSW,
			fmt.Sprintf("SAML signature algorithm weak on %s (%s = %s)", target, name, r.SignatureAlgo),
			target,
			models.SeverityHigh,
			fmt.Sprintf("signature_algorithm=%s", r.SignatureAlgo),
			"The SAML signature uses SHA-1, which is no longer collision-resistant. An attacker who can find a SHA-1 collision can produce a forged signature.",
			"SHAttered (https://shattered.io) demonstrated practical SHA-1 collisions.",
			"Configure the IdP / SP to use SHA-256 (rsa-sha256) or stronger. Disable rsa-sha1 in the metadata.",
		))
	}
	// Assertion replay — multiple identical assertions in the same Response.
	if len(r.Assertions) > 1 {
		findings = append(findings, F(
			VectorSAMLReplay,
			fmt.Sprintf("SAML response with %d assertions on %s (%s) — XSW possible", len(r.Assertions), target, name),
			target,
			models.SeverityHigh,
			fmt.Sprintf("assertion_count=%d", len(r.Assertions)),
			"Multiple Assertion blocks in the same Response is the classic Signature Wrapping (XSW) primitive: the SP validates the first Assertion (signed) but uses the second (unsigned) for the actual subject. The attacker controls the unsigned subject.",
			"SAML Raider / 'SAML XSW' (Burp extension) — wrap a forged Assertion as a sibling of the signed one.",
			"Reject Responses with more than one Assertion. If multiple are required, explicitly verify the signature on every Assertion and reject if any one fails.",
		))
	}
	// Assertion replay — past NotOnOrAfter + missing NotBefore / NotOnOrAfter.
	for _, a := range r.Assertions {
		if a.NotOnOrAfter.IsZero() {
			findings = append(findings, F(
				VectorSAMLReplay,
				fmt.Sprintf("SAML assertion without NotOnOrAfter on %s (%s)", target, name),
				target,
				models.SeverityHigh,
				"assertion_id="+a.ID,
				"The Assertion has no NotOnOrAfter — once captured, the assertion is valid forever.",
				"Capture a signed assertion and replay it at any time.",
				"All Assertions must include Conditions/@NotOnOrAfter. Reject any Assertion that lacks this attribute.",
			))
		} else if a.NotOnOrAfter.Before(time.Now()) {
			findings = append(findings, F(
				VectorSAMLReplay,
				fmt.Sprintf("SAML assertion expired on %s (%s) — %s", target, name, a.NotOnOrAfter),
				target,
				models.SeverityInfo,
				fmt.Sprintf("assertion_id=%s not_on_or_after=%s", a.ID, a.NotOnOrAfter),
				"The Assertion's NotOnOrAfter is in the past. If the SP does not enforce NotOnOrAfter, replay is possible.",
				"Replay the assertion and observe whether the SP still accepts it.",
				"Enforce Conditions/@NotOnOrAfter with a small clock-skew tolerance (≤60s).",
			))
		}
		if a.NotBefore.IsZero() {
			findings = append(findings, F(
				VectorSAMLReplay,
				fmt.Sprintf("SAML assertion without NotBefore on %s (%s)", target, name),
				target,
				models.SeverityMedium,
				"assertion_id="+a.ID,
				"The Assertion has no NotBefore — an old assertion captured before its nominal start could still be accepted.",
				"Capture an assertion now and replay it later; absence of NotBefore widens the replay window.",
				"Require NotBefore and enforce a small clock-skew tolerance.",
			))
		}
		if !a.HasNameID {
			findings = append(findings, F(
				VectorSAMLXSW,
				fmt.Sprintf("SAML assertion without <NameID> on %s (%s)", target, name),
				target,
				models.SeverityHigh,
				"nameid_present=false",
				"The Assertion has no <Subject>/<NameID> — the SP will fall back to whatever subject it parses first.",
				"Inject an <Assertion> with a malicious <NameID> alongside the (signed, no-subject) one.",
				"Reject Assertions without an explicit <NameID>.",
			))
		}
	}
	return findings
}

// --- minimal XML helpers --------------------------------------------------

var assertionRe = regexp.MustCompile(`(?s)<[^>]*Assertion[\s>].*?</[^>]*Assertion>`)

func extractAssertions(xml string) []SAMLAssertion {
	out := []SAMLAssertion{}
	for _, m := range assertionRe.FindAllString(xml, -1) {
		a := SAMLAssertion{}
		a.ID = attrValue(m, "Assertion", "ID")
		a.Subject = firstXMLElementContent(m, "NameID")
		a.HasNameID = a.Subject != ""
		a.Issuer = firstXMLElementContent(m, "Issuer")
		conditionsBlock := extractBlock(m, "Conditions")
		if conditionsBlock != "" {
			t := attrValue(conditionsBlock, "Conditions", "NotBefore")
			if t != "" {
				if parsed, err := time.Parse(time.RFC3339, t); err == nil {
					a.NotBefore = parsed
				}
			}
			t = attrValue(conditionsBlock, "Conditions", "NotOnOrAfter")
			if t != "" {
				if parsed, err := time.Parse(time.RFC3339, t); err == nil {
					a.NotOnOrAfter = parsed
				}
			}
			for _, aud := range audienceRe.FindAllStringSubmatch(conditionsBlock, -1) {
				if len(aud) > 1 {
					a.Audience = append(a.Audience, aud[1])
				}
			}
		}
		a.HasComments = strings.Contains(m, "<!--")
		out = append(out, a)
	}
	return out
}

var audienceRe = regexp.MustCompile(`<[^>]*Audience[\s>]*>([^<]+)</[^>]*Audience>`)

func extractBlock(xml, tag string) string {
	openRe := regexp.MustCompile(`<[^>]*` + tag + `[\s>][^>]*>`)
	closeRe := regexp.MustCompile(`</[^>]*` + tag + `>`)
	open := openRe.FindString(xml)
	if open == "" {
		return ""
	}
	idx := strings.Index(xml, open)
	if idx < 0 {
		return ""
	}
	close := closeRe.FindString(xml[idx+len(open):])
	if close == "" {
		return ""
	}
	return xml[idx : idx+len(open)+strings.Index(xml[idx+len(open):], close)+len(close)]
}

var elementRe = regexp.MustCompile(`<[^>]*%s[\s>]*>([^<]*)</[^>]*%s>`)

func firstXMLElementContent(xml, tag string) string {
	re := regexp.MustCompile(fmt.Sprintf(`<[^>]*%s[\s>]*>([^<]*)</[^>]*%s>`, tag, tag))
	if m := re.FindStringSubmatch(xml); len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

func attrValue(xml, tag, attr string) string {
	re := regexp.MustCompile(`<[^>]*` + tag + `[^>]*\s` + attr + `="([^"]*)"`)
	if m := re.FindStringSubmatch(xml); len(m) > 1 {
		return m[1]
	}
	return ""
}

func firstSignatureAlgo(xml string) string {
	re := regexp.MustCompile(`<[^>]*SignatureMethod[^>]*Algorithm="([^"]*)"`)
	if m := re.FindStringSubmatch(xml); len(m) > 1 {
		return m[1]
	}
	return ""
}

// suppress the unused-elementRe warning when stripping helper code
var _ = elementRe
