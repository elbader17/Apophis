package tokens

import (
	"strings"
	"testing"
)

func TestDecodeJWTMalformed(t *testing.T) {
	if _, err := DecodeJWT("not.a.jwt"); err == nil {
		t.Fatal("expected error on missing segs")
	}
	if _, err := DecodeJWT("a.b"); err == nil {
		t.Fatal("expected error on 2 segs")
	}
}

func TestDecodeJWTAlgNone(t *testing.T) {
	// Header: {"alg":"none","typ":"JWT"}  Payload: {"sub":"admin","exp":9999999999}
	hdr := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0"
	pay := "eyJzdWIiOiJhZG1pbiIsImV4cCI6OTk5OTk5OTk5OX0"
	sig := "" // empty signature
	j, err := DecodeJWT(hdr + "." + pay + "." + sig)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if j.Header.Alg != "none" {
		t.Fatalf("expected alg=none, got %q", j.Header.Alg)
	}
	findings := JWTInspect("t", "test", j)
	if len(findings) == 0 {
		t.Fatal("expected findings for alg=none JWT")
	}
	hasAlgNone := false
	for _, f := range findings {
		if f.Title == "" {
			t.Fatal("finding with empty title")
		}
		if strings.Contains(f.Title, "alg=none") {
			hasAlgNone = true
		}
	}
	if !hasAlgNone {
		t.Fatalf("expected alg=none finding, got %+v", findings)
	}
}

func TestDecodeJWTKidTraversal(t *testing.T) {
	// Header with a path-traversal kid
	hdr := "eyJhbGciOiJIUzI1NiIsImtpZCI6Ii4uLy4uLy4uLy9ldGMvcGFzc3dkIn0"
	pay := "eyJzdWIiOiJ0ZXN0In0"
	j, err := DecodeJWT(hdr + "." + pay + ".sig")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	findings := JWTInspect("t", "test", j)
	has := false
	for _, f := range findings {
		if strings.Contains(f.Title, "kid") && strings.Contains(f.Title, "traversal") {
			has = true
		}
	}
	if !has {
		t.Fatalf("expected kid-traversal finding, got %+v", findings)
	}
}

func TestBruteForceJWTSecretFound(t *testing.T) {
	// Mint a JWT signed with one of our bundled weak secrets.
	secret := "secret"
	hdr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" // {"alg":"HS256","typ":"JWT"}
	pay := "eyJzdWIiOiJ0ZXN0In0"                  // {"sub":"test"}
	raw := hdr + "." + pay
	sig, _ := verifyHMACForTest("HS256", raw, secret)
	enc := base64RawURLEncode(sig)
	j, err := DecodeJWT(raw + "." + enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	got, ok := BruteForceJWTSecret(j)
	if !ok || got != secret {
		t.Fatalf("expected to recover %q, got %q (ok=%v)", secret, got, ok)
	}
}

func TestBruteForceJWTSecretNotFound(t *testing.T) {
	hdr := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
	pay := "eyJzdWIiOiJ0ZXN0In0"
	raw := hdr + "." + pay
	sig, _ := verifyHMACForTest("HS256", raw, "this-secret-is-not-in-the-bundled-top-1000-list-it-is-purposely-very-long-to-avoid-collisions")
	enc := base64RawURLEncode(sig)
	j, _ := DecodeJWT(raw + "." + enc)
	if _, ok := BruteForceJWTSecret(j); ok {
		t.Fatal("expected no match for non-bundled secret")
	}
}

func TestParseSAMLResponseXSW(t *testing.T) {
	// Craft a SAML Response with two <Assertion> blocks (the XSW primitive).
	xml := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example</saml:Issuer>
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo></ds:Signature>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">
    <saml:Subject><saml:NameID>legitimate@user</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2030-01-01T00:00:00Z"/>
  </saml:Assertion>
  <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a2">
    <saml:Subject><saml:NameID>attacker@evil</saml:NameID></saml:Subject>
    <saml:Conditions NotBefore="2020-01-01T00:00:00Z" NotOnOrAfter="2030-01-01T00:00:00Z"/>
  </saml:Assertion>
</samlp:Response>`
	r, err := ParseSAMLResponse(xml)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(r.Assertions) != 2 {
		t.Fatalf("expected 2 assertions, got %d", len(r.Assertions))
	}
	findings := SAMLInspect("t", "test", r)
	has := false
	for _, f := range findings {
		if strings.Contains(f.Title, "assertions") && strings.Contains(f.Title, "XSW") {
			has = true
		}
	}
	if !has {
		t.Fatalf("expected XSW finding, got %+v", findings)
	}
}

func TestParseSAMLResponseNoNotOnOrAfter(t *testing.T) {
	xml := `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a1">
  <saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject>
</saml:Assertion>`
	r, _ := ParseSAMLResponse(xml)
	findings := SAMLInspect("t", "test", r)
	has := false
	for _, f := range findings {
		if strings.Contains(f.Title, "NotOnOrAfter") {
			has = true
		}
	}
	if !has {
		t.Fatalf("expected missing-NotOnOrAfter finding, got %+v", findings)
	}
}

func TestOAuthInspectWildcardRedirect(t *testing.T) {
	cfg := OAuthConfig{AuthEndpoint: "https://idp/auth", RedirectURI: "https://*.example.com/cb"}
	findings := OAuthInspect("t", cfg)
	if len(findings) == 0 {
		t.Fatal("expected findings for wildcard redirect_uri")
	}
}

func TestOAuthInspectStateMissing(t *testing.T) {
	findings := OAuthStateCheck("t", "https://idp/auth?client_id=abc&response_type=code")
	if len(findings) == 0 {
		t.Fatal("expected finding for missing state")
	}
}

func TestOAuthInspectStateShort(t *testing.T) {
	findings := OAuthStateCheck("t", "https://idp/auth?state=abc")
	if len(findings) == 0 {
		t.Fatal("expected finding for short state")
	}
}

func TestWeakSecretsLoaded(t *testing.T) {
	if len(WeakSecrets) < 50 {
		t.Fatalf("expected at least 50 bundled secrets, got %d", len(WeakSecrets))
	}
	// Dedup
	seen := map[string]bool{}
	for _, s := range WeakSecrets {
		if seen[s] {
			continue
		}
		seen[s] = true
	}
	if len(seen) != len(WeakSecrets) {
		t.Fatalf("duplicates in weak secrets list")
	}
}
