package poc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuditLogAppendAndRead(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "secret.key")
	al, err := OpenAuditLog(dir, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	rec := &AuditRecord{
		StartedAt:  time.Now(),
		FinishedAt: time.Now(),
		PoC:        AuditPoC{ID: "EDB-1", CVE: "CVE-2023-1234", Risk: "rce"},
		Target:     "10.10.10.5",
		Sandbox:    AuditSandbox{Level: "L1"},
		Cmd:        []string{"python3", "/tmp/poc.py"},
		ExitCode:   0,
		Stdout:     "vulnerable\n",
	}
	id, err := al.Append(rec)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(id, "exe-") {
		t.Fatalf("expected id to start with exe-, got %q", id)
	}
	back, err := al.Read(id)
	if err != nil {
		t.Fatal(err)
	}
	if back.PoC.ID != "EDB-1" {
		t.Fatalf("round-trip mismatch: %q", back.PoC.ID)
	}
	if back.HMAC == "" {
		t.Fatal("expected HMAC to be present after read")
	}
}

func TestAuditLogTamperDetected(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "secret.key")
	al, err := OpenAuditLog(dir, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	rec := &AuditRecord{
		StartedAt: time.Now(),
		PoC:       AuditPoC{ID: "EDB-2", Risk: "rce"},
		Target:    "10.10.10.5",
		Sandbox:   AuditSandbox{Level: "L1"},
		ExitCode:  0,
		Stdout:    "ok",
	}
	id, _ := al.Append(rec)

	// tamper with the file: chmod to writable, then replace "ok" with "POISONED"
	path := filepath.Join(dir, id+".json")
	_ = os.Chmod(path, 0644)
	body, _ := os.ReadFile(path)
	body = []byte(strings.Replace(string(body), `"ok"`, `"POISONED"`, 1))
	if err := os.WriteFile(path, body, 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := al.Read(id); err == nil {
		t.Fatal("expected HMAC mismatch on tampered record, got nil error")
	}
}

func TestAuditLogList(t *testing.T) {
	dir := t.TempDir()
	al, _ := OpenAuditLog(dir, "")
	for i := 0; i < 5; i++ {
		rec := &AuditRecord{
			StartedAt: time.Now().Add(time.Duration(i) * time.Second),
			PoC:       AuditPoC{ID: "EDB-" + string(rune('A'+i))},
			Target:    "10.10.10.5",
			Sandbox:   AuditSandbox{Level: "L1"},
		}
		_, _ = al.Append(rec)
	}
	entries, err := al.List(time.Time{}, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("expected 5 entries, got %d", len(entries))
	}
}
