package snmp

import "testing"

func TestDefaultCommunitiesNonEmpty(t *testing.T) {
	if len(defaults) < 5 {
		t.Fatalf("expected at least 5 default communities, got %d", len(defaults))
	}
	for _, c := range defaults {
		if c == "" {
			t.Fatal("empty community in defaults")
		}
	}
}

func TestBuildSNMPGetBulk(t *testing.T) {
	b := buildSNMPGetBulk("public", []string{"1.3.6.1.2.1.1.1.0"})
	if len(b) == 0 {
		t.Fatal("empty packet")
	}
	if b[0] != 0x30 {
		t.Fatalf("expected outer SEQUENCE (0x30), got 0x%02x", b[0])
	}
}

func TestEncodeOIDBER(t *testing.T) {
	if out := encodeOIDBER("1.3.6.1.2.1.1.1.0"); len(out) == 0 {
		t.Fatal("encodeOIDBER produced empty output")
	}
}

func TestDecodeLenShort(t *testing.T) {
	if v, h := decodeLen([]byte{0x05}); v != 5 || h != 1 {
		t.Errorf("decodeLen short: v=%d h=%d", v, h)
	}
	if v, h := decodeLen([]byte{0x81, 0x80}); v != 0x80 || h != 2 {
		t.Errorf("decodeLen 1byte: v=%d h=%d", v, h)
	}
}

func TestEncodeBase128(t *testing.T) {
	cases := map[int][]byte{
		0:     {0x00},
		127:   {0x7f},
		128:   {0x81, 0x00},
		300:   {0x82, 0x2c},
		16383: {0xff, 0x7f},
	}
	for in, want := range cases {
		got := encodeBase128(in)
		if len(got) != len(want) {
			t.Errorf("encodeBase128(%d) len=%d want %d", in, len(got), len(want))
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("encodeBase128(%d) byte %d: got 0x%02x want 0x%02x", in, i, got[i], want[i])
			}
		}
	}
}
