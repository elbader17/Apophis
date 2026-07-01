package webauth

import (
	"net/http"
	"strings"
	"testing"
)

func TestCookieAuditMissingSecure(t *testing.T) {
	hh := http.Header{}
	hh.Add("Set-Cookie", "PHPSESSID=abc123; Path=/; HttpOnly")
	findings := CookieAudit("t", hh, nil)
	if len(findings) == 0 {
		t.Fatal("expected Secure finding")
	}
	hasSecure := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Secure") {
			hasSecure = true
		}
	}
	if !hasSecure {
		t.Fatalf("expected Secure flag finding, got %+v", findings)
	}
}

func TestCookieAuditMissingSameSite(t *testing.T) {
	hh := http.Header{}
	hh.Add("Set-Cookie", "PHPSESSID=abc123; Path=/; Secure; HttpOnly")
	findings := CookieAudit("t", hh, nil)
	hasSameSite := false
	for _, f := range findings {
		if strings.Contains(f.Title, "SameSite") {
			hasSameSite = true
		}
	}
	if !hasSameSite {
		t.Fatalf("expected SameSite finding, got %+v", findings)
	}
}

func TestCSRFCheckMissing(t *testing.T) {
	body := `<html><body><form action="/login" method="POST"><input name="username"><input name="password"><input type="submit"></form></body></html>`
	findings := CSRFCheck("t", body, "csrf_token")
	if len(findings) == 0 {
		t.Fatal("expected CSRF missing finding")
	}
}

func TestCSRFCheckShort(t *testing.T) {
	body := `<html><body><form action="/login" method="POST"><input name="csrf_token" value="abc"><input type="submit"></form></body></html>`
	findings := CSRFCheck("t", body, "csrf_token")
	has := false
	for _, f := range findings {
		if strings.Contains(f.Title, "too short") {
			has = true
		}
	}
	if !has {
		t.Fatalf("expected short CSRF finding, got %+v", findings)
	}
}

func TestCSRFCheckOK(t *testing.T) {
	body := `<html><body><form action="/login" method="POST"><input name="csrf_token" value="0123456789abcdef0123456789abcdef"><input type="submit"></form></body></html>`
	findings := CSRFCheck("t", body, "csrf_token")
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestResetHostHeaderCheckPlainHTTP(t *testing.T) {
	findings := ResetHostHeaderCheck("t", "http://attacker.example/reset?token=xyz", "app.example.com")
	if len(findings) == 0 {
		t.Fatal("expected plain-HTTP finding")
	}
}

func TestResetHostHeaderCheckTemplate(t *testing.T) {
	findings := ResetHostHeaderCheck("t", "https://{HOST}/reset?token=xyz", "app.example.com")
	hasCritical := false
	for _, f := range findings {
		if string(f.Severity) == "CRITICAL" && strings.Contains(f.Title, "Host header") {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Fatalf("expected critical Host-header template finding, got %+v", findings)
	}
}

func TestRateLimitCheckTriggers(t *testing.T) {
	findings := RateLimitCheck("t", 200, "", "invalid password", 10)
	if len(findings) == 0 {
		t.Fatal("expected rate-limit finding")
	}
}

func TestRateLimitCheckLockedRecognised(t *testing.T) {
	findings := RateLimitCheck("t", 200, "", "Account temporarily disabled", 10)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when locked, got %+v", findings)
	}
}

func TestMFAEnforcementGapEmitsFinding(t *testing.T) {
	f := MFAFingerprint{HasMFA: false, MFAParameters: []string{"otp"}}
	findings := MFAEnforcementGap("t", "<form></form>", []string{"/admin", "/wire"}, f)
	if len(findings) == 0 {
		t.Fatal("expected MFA gap finding")
	}
}

func TestMFAEnforcementGapNoFindingWhenHasMFA(t *testing.T) {
	f := MFAFingerprint{HasMFA: true}
	findings := MFAEnforcementGap("t", "<form></form>", []string{"/admin"}, f)
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestBackupCodeSurfaceTriggers(t *testing.T) {
	findings := BackupCodeSurface("t", 10, 8, true)
	if len(findings) == 0 {
		t.Fatal("expected backup-code finding")
	}
}

func TestBackupCodeSurfaceRateLimited(t *testing.T) {
	findings := BackupCodeSurface("t", 10, 8, false)
	if len(findings) != 0 {
		t.Fatalf("expected no findings when rate-limited, got %+v", findings)
	}
}

func TestIsSensitiveCookie(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"PHPSESSID", true},
		{"session", true},
		{"JSESSIONID", true},
		{"theme", false},
	}
	for _, c := range cases {
		if got := isSensitiveCookie(c.in, nil); got != c.want {
			t.Errorf("isSensitiveCookie(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParseSetCookie(t *testing.T) {
	c := parseSetCookie("PHPSESSID=abc; Path=/; Secure; HttpOnly; SameSite=Lax")
	if c.Name != "PHPSESSID" || c.Value != "abc" {
		t.Errorf("name/value=%s/%s", c.Name, c.Value)
	}
	if !c.Secure || !c.HTTPOnly {
		t.Errorf("secure=%v httponly=%v", c.Secure, c.HTTPOnly)
	}
	if c.SameSite != "Lax" {
		t.Errorf("samesite=%s", c.SameSite)
	}
	if c.Path != "/" {
		t.Errorf("path=%s", c.Path)
	}
}
