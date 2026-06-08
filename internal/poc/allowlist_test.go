package poc

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAllowlistIPExact(t *testing.T) {
	a := NewAllowlist()
	if err := a.Add("10.10.10.5", "lab"); err != nil {
		t.Fatal(err)
	}
	ok, note := a.Contains("10.10.10.5")
	if !ok || note != "lab" {
		t.Fatalf("expected match with note, got ok=%v note=%q", ok, note)
	}
	if ok, _ := a.Contains("10.10.10.6"); ok {
		t.Fatal("unexpected match for 10.10.10.6")
	}
}

func TestAllowlistCIDR(t *testing.T) {
	a := NewAllowlist()
	if err := a.Add("10.10.11.0/24", "vulnhub"); err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.10.11.1", "10.10.11.100", "10.10.11.255"} {
		if ok, _ := a.Contains(ip); !ok {
			t.Errorf("expected %s to match CIDR", ip)
		}
	}
	if ok, _ := a.Contains("10.10.12.1"); ok {
		t.Errorf("10.10.12.1 should not match 10.10.11.0/24")
	}
}

func TestAllowlistHostname(t *testing.T) {
	a := NewAllowlist()
	if err := a.Add("scanme.nmap.org", ""); err != nil {
		t.Fatal(err)
	}
	if ok, _ := a.Contains("scanme.nmap.org"); !ok {
		t.Fatal("expected exact hostname match")
	}
}

func TestAllowlistInvalid(t *testing.T) {
	a := NewAllowlist()
	if err := a.Add("!@#$.example.com", ""); err == nil {
		t.Fatal("expected error for invalid hostname (special chars)")
	}
	if err := a.Add("-leading.example.com", ""); err == nil {
		t.Fatal("expected error for invalid hostname (leading hyphen)")
	}
	if err := a.Add("10.0.0.0/99", ""); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
	if err := a.Add("", ""); err == nil {
		t.Fatal("expected error for empty target")
	}
}

func TestAllowlistFileLoad(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "allowlist.txt")
	content := `# test allowlist
10.10.10.5     # lab
10.10.11.0/24  # subnet
scanme.nmap.org
`
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	al, err := LoadAllowlistFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if al.Len() != 3 {
		t.Fatalf("expected 3 entries, got %d", al.Len())
	}
	if ok, _ := al.Contains("10.10.10.5"); !ok {
		t.Fatal("expected 10.10.10.5 to match")
	}
	if ok, _ := al.Contains("10.10.11.42"); !ok {
		t.Fatal("expected 10.10.11.42 to match CIDR")
	}
}

func TestAllowlistListSorted(t *testing.T) {
	a := NewAllowlist()
	for _, e := range []string{"scanme.nmap.org", "10.10.10.5", "10.10.11.0/24"} {
		if err := a.Add(e, ""); err != nil {
			t.Fatal(err)
		}
	}
	list := a.List()
	if len(list) != 3 {
		t.Fatalf("expected 3 entries, got %d (%v)", len(list), list)
	}
	if list[0] != "10.10.10.5" {
		t.Fatalf("expected first sorted to be 10.10.10.5, got %q", list[0])
	}
}

func TestAllowlistRemove(t *testing.T) {
	a := NewAllowlist()
	a.Add("10.10.10.5", "")
	if !a.Remove("10.10.10.5") {
		t.Fatal("expected remove to succeed")
	}
	if ok, _ := a.Contains("10.10.10.5"); ok {
		t.Fatal("expected 10.10.10.5 to be gone")
	}
	if a.Remove("10.10.10.5") {
		t.Fatal("expected second remove to fail")
	}
}
