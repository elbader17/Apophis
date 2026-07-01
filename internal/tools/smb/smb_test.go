package smb

import (
	"testing"

	"github.com/apophis-eng/apophis/internal/models"
)

func TestIsSMB1Response(t *testing.T) {
	if !isSMB1Response(append([]byte{0xff, 'S', 'M', 'B', 0x72}, make([]byte, 30)...)) {
		t.Fatal("expected SMB1 response to be detected")
	}
	if isSMB1Response([]byte{0xfe, 'S', 'M', 'B'}) {
		t.Fatal("SMB2 response should not be classified as SMB1")
	}
}

func TestIsSMB2Response(t *testing.T) {
	if !isSMB2Response([]byte{0xfe, 'S', 'M', 'B'}) {
		t.Fatal("expected SMB2 response to be detected")
	}
	if isSMB2Response([]byte{0xff, 'S', 'M', 'B'}) {
		t.Fatal("SMB1 response should not be classified as SMB2")
	}
}

func TestBuildSMB1Negotiate(t *testing.T) {
	pkt := buildSMB1Negotiate()
	if len(pkt) < 12 {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}
	// NetBIOS session message prefix is a single 0x00 byte.
	if pkt[0] != netbiosSessionMsg {
		t.Fatalf("NetBIOS session type should be 0x00, got 0x%02x", pkt[0])
	}
	// Length high byte for a 50-byte payload is 0, low byte is non-zero.
	if pkt[2] != 0 || pkt[1] == 0 {
		t.Fatalf("NetBIOS length should be encoded in pkt[1] (low byte), got pkt[1]=%d pkt[2]=%d", pkt[1], pkt[2])
	}
}

func TestBuildSMB2Negotiate(t *testing.T) {
	pkt := buildSMB2Negotiate()
	if len(pkt) < 64 {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}
	if pkt[0] != 0 {
		t.Fatal("NetBIOS type should be 0")
	}
}

func TestBuildSMB1NullSession(t *testing.T) {
	pkt := buildSMB1NullSession()
	if len(pkt) < 32 {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}
}

func TestBuildSMB1NetShareEnumAll(t *testing.T) {
	pkt := buildSMB1NetShareEnumAll()
	if len(pkt) < 32 {
		t.Fatalf("packet too short: %d bytes", len(pkt))
	}
}

func TestPickPort(t *testing.T) {
	if got := pickPort(nil); got != 0 {
		t.Fatalf("nil ports should yield 0, got %d", got)
	}
	ports := []models.PortInfo{
		{Port: 443}, {Port: 445}, {Port: 8080},
	}
	if got := pickPort(ports); got != 445 {
		t.Fatalf("expected 445, got %d", got)
	}
	ports = []models.PortInfo{
		{Port: 443}, {Port: 139},
	}
	if got := pickPort(ports); got != 139 {
		t.Fatalf("expected fallback to 139, got %d", got)
	}
}

func TestExtractOSString(t *testing.T) {
	if got := extractOSString(make([]byte, 4)); got != "" {
		t.Fatalf("expected empty for short input, got %q", got)
	}
}
