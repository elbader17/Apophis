package ldap

import (
	"testing"
)

func TestBuildBindRequest(t *testing.T) {
	b := buildBindRequest(1, "", "")
	if len(b) < 12 {
		t.Fatalf("bind request too short: %d bytes", len(b))
	}
	if b[0] != 0x30 {
		t.Fatalf("expected outer SEQUENCE, got 0x%02x", b[0])
	}
}

func TestBuildSearchRequest(t *testing.T) {
	b := buildSearchRequest(2, "", "(objectClass=*)")
	if len(b) < 12 {
		t.Fatalf("search request too short: %d bytes", len(b))
	}
	if b[0] != 0x30 {
		t.Fatalf("expected outer SEQUENCE, got 0x%02x", b[0])
	}
}

func TestDecodeLen(t *testing.T) {
	cases := []struct {
		b    []byte
		want int
		hdr  int
	}{
		{[]byte{0x05}, 5, 1},
		{[]byte{0x81, 0x80}, 0x80, 2},
		{[]byte{0x82, 0x01, 0x00}, 256, 3},
	}
	for _, c := range cases {
		v, h := decodeLen(c.b)
		if v != c.want || h != c.hdr {
			t.Errorf("decodeLen(%v) = v=%d h=%d, want v=%d h=%d", c.b, v, h, c.want, c.hdr)
		}
	}
}

func TestBERLen(t *testing.T) {
	if out := berLen(5); len(out) != 1 || out[0] != 5 {
		t.Errorf("berLen(5) = %v", out)
	}
	if out := berLen(0x80); len(out) != 2 || out[0] != 0x81 || out[1] != 0x80 {
		t.Errorf("berLen(0x80) = %v", out)
	}
}

func TestReadStrings(t *testing.T) {
	// Two consecutive OCTET STRINGs.
	b := []byte{0x04, 0x02, 'h', 'i', 0x04, 0x05, 'h', 'e', 'l', 'l', 'o'}
	got := readStrings(b)
	if len(got) != 2 {
		t.Fatalf("expected 2 strings, got %d: %v", len(got), got)
	}
	if got[0] != "hi" {
		t.Errorf("first string: %q", got[0])
	}
	if got[1] != "hello" {
		t.Errorf("second string: %q", got[1])
	}
}

func TestGuessServerTypeByVendor(t *testing.T) {
	d := &searchResult{vendorName: "Active Directory"}
	if guessServerType(d) != "Active Directory" {
		t.Errorf("expected Active Directory, got %q", guessServerType(d))
	}
	d = &searchResult{vendorName: "OpenLDAP 2.4"}
	if guessServerType(d) != "OpenLDAP" {
		t.Errorf("expected OpenLDAP, got %q", guessServerType(d))
	}
	d = &searchResult{defaultNamingContext: "DC=corp,DC=local"}
	if guessServerType(d) != "Active Directory (no vendorName)" {
		t.Errorf("expected AD hint by naming context, got %q", guessServerType(d))
	}
}
