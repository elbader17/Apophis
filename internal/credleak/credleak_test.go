package credleak

import (
	"strings"
	"testing"
)

func TestEntropyDetectorHighEntropy(t *testing.T) {
	body := `config = { password: "x9K!pL2$mN8qR5vT3wY7zA1bC4dE6fG" }`
	d := NewEntropyDetector()
	findings := d.Scan("t", body)
	if len(findings) == 0 {
		t.Fatal("expected finding for high-entropy password")
	}
}

func TestEntropyDetectorLowEntropy(t *testing.T) {
	body := `config = { password: "abc" }`
	d := NewEntropyDetector()
	findings := d.Scan("t", body)
	if len(findings) != 0 {
		t.Fatalf("expected no finding for low-entropy value, got %+v", findings)
	}
}

func TestHardcodedAWSKey(t *testing.T) {
	body := `aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"`
	findings := ScanHardcoded("t", body)
	has := false
	for _, f := range findings {
		if strings.Contains(f.Title, "AWS Access Key ID") {
			has = true
		}
	}
	if !has {
		t.Fatalf("expected AWS Access Key ID finding, got %+v", findings)
	}
}

func TestHardcodedGitHubToken(t *testing.T) {
	body := `const GITHUB_TOKEN = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";`
	findings := ScanHardcoded("t", body)
	has := false
	for _, f := range findings {
		if strings.Contains(f.Title, "GitHub personal access token") {
			has = true
		}
	}
	if !has {
		t.Fatalf("expected GitHub PAT finding, got %+v", findings)
	}
}

func TestHardcodedPrivateKey(t *testing.T) {
	body := `-----BEGIN RSA PRIVATE KEY-----`
	findings := ScanHardcoded("t", body)
	has := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Private key") {
			has = true
		}
	}
	if !has {
		t.Fatalf("expected private key finding, got %+v", findings)
	}
}

func TestHardcodedNoFindingForCleanResponse(t *testing.T) {
	body := `<html><body>Hello world</body></html>`
	findings := ScanHardcoded("t", body)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for clean response, got %+v", findings)
	}
}

func TestHardcodedDedup(t *testing.T) {
	body := `AKIAIOSFODNN7EXAMPLE and also AKIAIOSFODNN7EXAMPLE`
	findings := ScanHardcoded("t", body)
	if len(findings) > 1 {
		t.Fatalf("expected dedup'd findings, got %d", len(findings))
	}
}

func TestBackupFileScanHit(t *testing.T) {
	hits := map[string]BackupFileHit{
		".env": {Path: ".env", Status: 200, BodySize: 1024},
	}
	findings := BackupFileScan("t", hits)
	if len(findings) == 0 {
		t.Fatal("expected finding for .env hit")
	}
	if findings[0].Severity == "" {
		t.Fatal("expected non-empty severity")
	}
}

func TestBackupFileScanNoHit(t *testing.T) {
	hits := map[string]BackupFileHit{
		".env": {Path: ".env", Status: 404, BodySize: 0},
	}
	findings := BackupFileScan("t", hits)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for 404, got %d", len(findings))
	}
}

func TestBackupFilesCatalogSize(t *testing.T) {
	if len(BackupFiles) < 50 {
		t.Fatalf("expected >= 50 backup file probes, got %d", len(BackupFiles))
	}
}

func TestCommitMessageLeakDetectsPassword(t *testing.T) {
	body := "fix: bump version\npassword reset for production deployment to db=prod\nrelease: 1.0.0"
	findings := CommitMessageLeak("t", body)
	if len(findings) == 0 {
		t.Fatal("expected commit message leak finding")
	}
}

func TestCommitMessageLeakIgnoresCommon(t *testing.T) {
	body := "fix: bump version\nrelease: 1.0.0\nrefactor: rename"
	findings := CommitMessageLeak("t", body)
	if len(findings) != 0 {
		t.Fatalf("expected no findings for clean log, got %d", len(findings))
	}
}

func TestShannonEntropyKnownValues(t *testing.T) {
	if shannonEntropy("aaaa") > 0.1 {
		t.Error("entropy(aaaa) should be ~0")
	}
	if shannonEntropy("abcd") < 2.0 {
		t.Error("entropy(abcd) should be 2.0")
	}
}
