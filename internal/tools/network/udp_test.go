package network

import (
	"testing"
)

func TestUDPProbePayload(t *testing.T) {
	cases := map[string][]byte{
		"dns":        udpProbePayload("dns"),
		"ntp":        udpProbePayload("ntp"),
		"snmp":       udpProbePayload("snmp"),
		"netbios-ns": udpProbePayload("netbios-ns"),
		"tftp":       udpProbePayload("tftp"),
		"sip":        udpProbePayload("sip"),
		"unknown":    udpProbePayload("bogus"),
	}
	for k, b := range cases {
		if k == "unknown" && b != nil {
			t.Errorf("unknown service should have no payload, got %v", b)
		}
		if k == "unknown" {
			continue
		}
		if len(b) == 0 {
			t.Errorf("service %s produced empty payload", k)
		}
	}
}

func TestGuessUDPService(t *testing.T) {
	cases := map[int]string{
		53:   "dns",
		123:  "ntp",
		161:  "snmp",
		137:  "netbios-ns",
		69:   "tftp",
		9999: "unknown",
	}
	for port, want := range cases {
		if got := guessUDPService(port); got != want {
			t.Errorf("port %d: got %q, want %q", port, got, want)
		}
	}
}

func TestDescribeUDPResponse(t *testing.T) {
	if s := describeUDPResponse("dns", make([]byte, 64)); s == "" {
		t.Fatal("dns description should be non-empty for valid buffer")
	}
	if s := describeUDPResponse("unknown", []byte("hello")); s == "" {
		t.Fatal("unknown service should still produce a description")
	}
}

func TestCommonUDPPorts(t *testing.T) {
	ports := CommonUDPPorts()
	if len(ports) < 10 {
		t.Fatalf("expected at least 10 UDP ports, got %d", len(ports))
	}
	// Sorted.
	for i := 1; i < len(ports); i++ {
		if ports[i] <= ports[i-1] {
			t.Fatalf("not sorted at %d: %d <= %d", i, ports[i], ports[i-1])
		}
	}
}

func TestEncodeOID(t *testing.T) {
	if out := encodeOID("1.3.6.1.2.1.1.1.0"); len(out) == 0 {
		t.Fatal("encodeOID produced empty output")
	}
}
