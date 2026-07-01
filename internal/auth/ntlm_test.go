package auth

import (
	"encoding/binary"
	"strings"
	"testing"
)

// Construct a minimal NTLMSSP Negotiate (Type 1) message and confirm the
// parser flags only the safe flags.
func TestParseNTLMSSPType1LowRisk(t *testing.T) {
	pkt := buildNTLMSSPType1()
	m := ParseNTLMMessage(pkt)
	if m == nil {
		t.Fatal("nil NTLMMessage")
	}
	if m.Type != NTLMNegotiate {
		t.Fatalf("expected Type=1, got %d", m.Type)
	}
	score, reasons := m.RiskScore()
	if score > 0 {
		t.Fatalf("expected score 0 for safe negotiate, got %d (reasons=%v)", score, reasons)
	}
}

// Build an NTLMSSP Negotiate that DOES set NegotiateLMKey and NegotiateOEM,
// then confirm the risk score is high.
func TestParseNTLMSSPType1HighRisk(t *testing.T) {
	pkt := buildNTLMSSPType1()
	// Patch the flags to include LMKey + OEM, drop NTLM.
	flags := uint32(NTLMFlagNegotiateLMKey |
		NTLMFlagNegotiateOEM |
		NTLMFlagNegotiateSign)
	binary.LittleEndian.PutUint32(pkt[12:16], flags)
	m := ParseNTLMMessage(pkt)
	score, reasons := m.RiskScore()
	if score < 30 {
		t.Fatalf("expected high risk score, got %d (reasons=%v)", score, reasons)
	}
	if !contains(reasons, "NegotiateLMKey") {
		t.Fatalf("expected NegotiateLMKey reason, got %v", reasons)
	}
}

func TestB64RoundTrip(t *testing.T) {
	for _, in := range [][]byte{
		[]byte("hello"),
		[]byte("Hello, world!"),
		{0x00, 0x01, 0x02, 0xff},
	} {
		s := b64(in)
		out, err := unb64(s)
		if err != nil {
			t.Fatalf("unb64(%q): %v", s, err)
		}
		if len(out) != len(in) {
			t.Errorf("len mismatch: in=%d out=%d (%q vs %q)", len(in), len(out), in, out)
		}
		for i := range in {
			if in[i] != out[i] {
				t.Errorf("byte %d: %02x vs %02x", i, in[i], out[i])
			}
		}
	}
}

func TestStripScheme(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"https://example.com/", "example.com/"},
		{"http://example.com/", "example.com/"},
		{"example.com/", "example.com/"},
	} {
		if got := stripScheme(c.in); got != c.want {
			t.Errorf("stripScheme(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func contains(s []string, want string) bool {
	for _, x := range s {
		if strings.Contains(x, want) {
			return true
		}
	}
	return false
}
