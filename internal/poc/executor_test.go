package poc

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExecutorDryRun(t *testing.T) {
	dir := t.TempDir()
	audit, _ := OpenAuditLog(dir, "")
	allow := NewAllowlist()
	_ = allow.Add("10.10.10.5", "lab")
	store, _ := OpenStore(filepath.Join(dir, "pocs"))

	cfg := ExecConfig{
		Enabled:          true,
		MaxRisk:          RiskRCE,
		ExecutionTimeout: 30 * time.Second,
		DryRun:           true,
		AuditDir:         dir,
	}
	exec := NewExecutor(cfg, audit, allow, store)
	_ = exec

	poc := &PoC{
		ID:        "EDB-1",
		CVE:       "CVE-2023-1234",
		Source:    "exploitdb",
		Title:     "Test PoC",
		Type:      PoCTypePython,
		Path:      "/tmp/poc.py",
		Raw:       "import socket\ns=socket.socket()\ns.connect((target,80))",
		Risk:      RiskSafe,
		Args:      []string{},
		Signature: Signature("import socket\ns=socket.socket()"),
	}
	if err := store.Save(poc); err != nil {
		t.Fatal(err)
	}

	res, err := exec.Run(context.Background(), RunRequest{
		PoC:          poc,
		Target:       "10.10.10.5",
		SandboxLevel: SandboxL1,
		TimeoutSec:   5,
		Confirm:      true,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !res.DryRun {
		t.Fatal("expected dry_run flag")
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d", res.ExitCode)
	}

	entries, _ := audit.List(time.Time{}, "", 0)
	if len(entries) != 1 {
		t.Fatalf("expected 1 audit entry, got %d", len(entries))
	}
}

func TestExecutorDisabled(t *testing.T) {
	dir := t.TempDir()
	audit, _ := OpenAuditLog(dir, "")
	allow := NewAllowlist()
	store, _ := OpenStore(filepath.Join(dir, "pocs"))

	cfg := ExecConfig{Enabled: false, MaxRisk: RiskRCE, AuditDir: dir}
	exec := NewExecutor(cfg, audit, allow, store)

	_, err := exec.Run(context.Background(), RunRequest{
		PoC:     &PoC{ID: "x", Type: PoCTypePython, Risk: RiskSafe},
		Target:  "10.10.10.5",
		Confirm: true,
	})
	if err == nil {
		t.Fatal("expected error when executor is disabled")
	}
}

func TestExecutorNotInAllowlist(t *testing.T) {
	dir := t.TempDir()
	audit, _ := OpenAuditLog(dir, "")
	allow := NewAllowlist()
	store, _ := OpenStore(filepath.Join(dir, "pocs"))

	cfg := ExecConfig{Enabled: true, MaxRisk: RiskRCE, AuditDir: dir}
	exec := NewExecutor(cfg, audit, allow, store)

	_, err := exec.Run(context.Background(), RunRequest{
		PoC:     &PoC{ID: "x", Type: PoCTypePython, Risk: RiskSafe},
		Target:  "8.8.8.8",
		Confirm: true,
	})
	if err == nil {
		t.Fatal("expected error for target not in allowlist")
	}
}

func TestExecutorRiskTooHigh(t *testing.T) {
	dir := t.TempDir()
	audit, _ := OpenAuditLog(dir, "")
	allow := NewAllowlist()
	_ = allow.Add("10.10.10.5", "")
	store, _ := OpenStore(filepath.Join(dir, "pocs"))

	cfg := ExecConfig{Enabled: true, MaxRisk: RiskSafe, AuditDir: dir}
	exec := NewExecutor(cfg, audit, allow, store)

	_, err := exec.Run(context.Background(), RunRequest{
		PoC:     &PoC{ID: "x", Type: PoCTypePython, Risk: RiskRCE},
		Target:  "10.10.10.5",
		Confirm: true,
	})
	if err == nil {
		t.Fatal("expected error for risk above max")
	}
}

func TestExecutorRequiresConfirm(t *testing.T) {
	dir := t.TempDir()
	audit, _ := OpenAuditLog(dir, "")
	allow := NewAllowlist()
	_ = allow.Add("10.10.10.5", "")
	store, _ := OpenStore(filepath.Join(dir, "pocs"))

	cfg := ExecConfig{Enabled: true, MaxRisk: RiskRCE, AuditDir: dir}
	exec := NewExecutor(cfg, audit, allow, store)

	_, err := exec.Run(context.Background(), RunRequest{
		PoC:     &PoC{ID: "x", Type: PoCTypePython, Risk: RiskSafe},
		Target:  "10.10.10.5",
		Confirm: false,
	})
	if err == nil {
		t.Fatal("expected error when confirm is missing")
	}
}

func TestExecutorTimeoutExceedsMax(t *testing.T) {
	dir := t.TempDir()
	audit, _ := OpenAuditLog(dir, "")
	allow := NewAllowlist()
	_ = allow.Add("10.10.10.5", "")
	store, _ := OpenStore(filepath.Join(dir, "pocs"))

	cfg := ExecConfig{
		Enabled:          true,
		MaxRisk:          RiskRCE,
		ExecutionTimeout: 10 * time.Second,
		AuditDir:         dir,
	}
	exec := NewExecutor(cfg, audit, allow, store)

	_, err := exec.Run(context.Background(), RunRequest{
		PoC:        &PoC{ID: "x", Type: PoCTypePython, Risk: RiskSafe},
		Target:     "10.10.10.5",
		Confirm:    true,
		TimeoutSec: 999,
	})
	if err == nil {
		t.Fatal("expected error for timeout exceeding max")
	}
}

func TestSandboxRunHello(t *testing.T) {
	if os.Getenv("APOPHIS_SKIP_SANDBOX_TEST") != "" {
		t.Skip("sandbox integration test skipped")
	}
	dir := t.TempDir()
	sandbox := NewL1Sandbox(L1Options{WorkDir: dir})
	res, err := sandbox.Run(context.Background(), "/bin/echo", []string{"/bin/echo", "hello"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("expected exit 0, got %d (stderr=%s)", res.ExitCode, res.Stderr)
	}
	if res.Stdout != "hello\n" && res.Stdout != "hello" {
		t.Fatalf("unexpected stdout: %q", res.Stdout)
	}
}
