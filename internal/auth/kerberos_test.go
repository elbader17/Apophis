package auth

import (
	"strings"
	"testing"
)

func TestDerLen(t *testing.T) {
	cases := []struct {
		in   int
		want []byte
	}{
		{0, []byte{0x00}},
		{5, []byte{0x05}},
		{127, []byte{0x7f}},
		{128, []byte{0x81, 0x80}},
		{255, []byte{0x81, 0xff}},
		{256, []byte{0x82, 0x01, 0x00}},
	}
	for _, c := range cases {
		got := derLen(c.in)
		if len(got) != len(c.want) {
			t.Errorf("derLen(%d) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("derLen(%d) byte %d: got 0x%02x want 0x%02x", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestDerInt(t *testing.T) {
	cases := map[int][]byte{
		0:   {0x02, 0x01, 0x00},
		5:   {0x02, 0x01, 0x05},
		127: {0x02, 0x01, 0x7f},
		128: {0x02, 0x02, 0x00, 0x80},
		256: {0x02, 0x02, 0x01, 0x00},
	}
	for in, want := range cases {
		got := derInt(in)
		if len(got) != len(want) {
			t.Errorf("derInt(%d) = %v, want %v", in, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("derInt(%d) byte %d: got 0x%02x want 0x%02x", in, i, got[i], want[i])
			}
		}
	}
}

func TestASReq(t *testing.T) {
	pkt := ASReq("CORP.LOCAL", []string{"alice"}, []int{23})
	if len(pkt) < 50 {
		t.Fatalf("AS-REQ too short: %d bytes", len(pkt))
	}
	// Outer tag is [APPLICATION 10] AS-REQ = 0x6a.
	if pkt[0] != 0x6a {
		t.Fatalf("expected AS-REQ tag 0x6a, got 0x%02x", pkt[0])
	}
	// KDC-REQ body SEQUENCE follows; inside it we have pvno [1] 5 + msg-type [2] 10.
	// We don't deeply parse here — just sanity-check that "alice" appears.
	if !strings.Contains(string(pkt), "alice") {
		t.Fatal("expected principal name to be present in AS-REQ bytes")
	}
}

func TestTGSReq(t *testing.T) {
	pkt := TGSReq("CORP.LOCAL", "http/web01.corp.local")
	if len(pkt) < 50 {
		t.Fatalf("TGS-REQ too short: %d bytes", len(pkt))
	}
	if pkt[0] != 0x6c {
		t.Fatalf("expected TGS-REQ tag 0x6c, got 0x%02x", pkt[0])
	}
}

func TestPrincipal(t *testing.T) {
	p := Principal(1, 1, "alice")
	// Principal is [1] CONSTRUCTED → tag 0xa1
	if p[0] != 0xa1 {
		t.Fatalf("expected [1] tag 0xa1, got 0x%02x", p[0])
	}
}

func TestParseASResponseNilForGarbage(t *testing.T) {
	if r := ParseASResponse([]byte{0x00, 0x01}); r != nil {
		t.Fatalf("expected nil for garbage input, got %+v", r)
	}
	if r := ParseASResponse([]byte{0x6b}); r != nil {
		t.Fatalf("expected nil for short AS-REP")
	}
}

func TestASResponseIsCrackable(t *testing.T) {
	r := &ASResponse{EncPartEtype: 23, HasEncPart: true}
	if !r.IsCrackable() {
		t.Fatal("RC4 AS-REP should be crackable")
	}
	r = &ASResponse{EncPartEtype: 18, HasEncPart: true}
	if r.IsCrackable() {
		t.Fatal("AES-256 AS-REP should not be crackable")
	}
	r = &ASResponse{IsError: true, ErrorCode: 25}
	if r.IsCrackable() {
		t.Fatal("KRB-ERROR should not be crackable")
	}
}
