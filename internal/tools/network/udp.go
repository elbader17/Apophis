package network

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

// commonUDPPorts is the curated set of UDP services worth probing. The
// service guess is used both for banner-style probes (DNS, NTP, SNMP) and
// for the resulting models.PortInfo.Service field.
var commonUDPPorts = map[int]string{
	53:    "dns",
	67:    "dhcp",
	68:    "dhcp-client",
	69:    "tftp",
	111:   "rpcbind",
	123:   "ntp",
	135:   "msrpc",
	137:   "netbios-ns",
	138:   "netbios-dgm",
	161:   "snmp",
	162:   "snmp-trap",
	389:   "ldap",
	500:   "isakmp",
	514:   "syslog",
	520:   "rip",
	1194:  "openvpn",
	1701:  "l2tp",
	1812:  "radius",
	1900:  "ssdp",
	2049:  "nfs",
	4500:  "ipsec-nat-t",
	5060:  "sip",
	5353:  "mdns",
	5683:  "coap",
	11211: "memcached",
}

type UDPScanner struct {
	timeout time.Duration
	// MaxConcurrent bounds the number of in-flight UDP probes. UDP sends
	// rarely get immediate ICMP-unreachable replies, so flooding the wire
	// gets us nowhere — 64 is a sensible default.
	MaxConcurrent int
	// SendPayload, when true, sends a protocol-specific probe (DNS query,
	// SNMP GET, NTP request) before deciding the port is open|filtered.
	// When false the scanner only does bare sends and marks any port that
	// produced no ICMP-unreachable as "open|filtered".
	SendPayload bool
}

func NewUDPScanner(timeout time.Duration) *UDPScanner {
	if timeout == 0 {
		timeout = 3 * time.Second
	}
	return &UDPScanner{timeout: timeout, MaxConcurrent: 64, SendPayload: true}
}

// CommonUDPPorts returns the curated UDP port list as a slice sorted by port.
func CommonUDPPorts() []int {
	out := make([]int, 0, len(commonUDPPorts))
	for p := range commonUDPPorts {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// Scan probes each UDP port. The returned PortInfo has Protocol="udp" and
// State one of "open", "open|filtered" or "filtered". A bare-send probe
// cannot distinguish "open" from "filtered" without seeing an ICMP
// unreachable, which is typically rate-limited or filtered at the network
// edge. We treat a parseable service reply as "open" and silence as
// "open|filtered" — both are interesting.
func (s *UDPScanner) Scan(ctx context.Context, host string, ports []int) []models.PortInfo {
	if len(ports) == 0 {
		ports = CommonUDPPorts()
	}
	resolved, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, "0"))
	if err != nil {
		return nil
	}

	concurrency := s.MaxConcurrent
	if concurrency <= 0 {
		concurrency = 64
	}
	sem := make(chan struct{}, concurrency)

	var (
		mu      sync.Mutex
		results = make([]models.PortInfo, 0)
		wg      sync.WaitGroup
	)
	for _, port := range ports {
		select {
		case <-ctx.Done():
			sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
			return results
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()
			info := s.probe(ctx, resolved, host, port)
			if info != nil {
				mu.Lock()
				results = append(results, *info)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	sort.Slice(results, func(i, j int) bool { return results[i].Port < results[j].Port })
	return results
}

func (s *UDPScanner) probe(ctx context.Context, resolved *net.UDPAddr, host string, port int) *models.PortInfo {
	dialer := net.Dialer{Timeout: s.timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil
	}
	defer conn.Close()

	svc := guessUDPService(port)
	payload := udpProbePayload(svc)
	state := "open|filtered"
	banner := ""
	if s.SendPayload && len(payload) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(s.timeout))
		if _, err := conn.Write(payload); err == nil {
			_ = conn.SetReadDeadline(time.Now().Add(s.timeout))
			buf := make([]byte, 512)
			n, _ := conn.Read(buf)
			if n > 0 {
				state = "open"
				banner = describeUDPResponse(svc, buf[:n])
			}
		}
	}
	return &models.PortInfo{
		Port:     port,
		Protocol: "udp",
		State:    state,
		Service:  svc,
		Banner:   banner,
	}
}

func guessUDPService(port int) string {
	if s, ok := commonUDPPorts[port]; ok {
		return s
	}
	return "unknown"
}

// udpProbePayload returns a minimal request for the given service that is
// enough to elicit a response from an open port. Anything that fails to
// elicit a response keeps the port in the "open|filtered" bucket.
func udpProbePayload(service string) []byte {
	switch service {
	case "dns":
		// Standard query for "version.bind" CHAOS TXT, recursion desired.
		return []byte{
			0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x07, 'v', 'e', 'r',
			's', 'i', 'o', 'n', 0x04, 'b', 'i', 'n', 'd', 0x00, 0x00, 0x10, 0x00, 0x03,
		}
	case "ntp":
		// NTPv3 client request (LI=0, VN=3, Mode=3).
		return []byte{0x1b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	case "snmp":
		// SNMPv2c GET for sysDescr.0 (1.3.6.1.2.1.1.1.0).
		// Community "public". Minimal valid ASN.1 BER.
		return buildSNMPGet("public", "1.3.6.1.2.1.1.1.0")
	case "netbios-ns":
		// Wildcard NBSTAT query.
		return []byte{
			0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x00, 0x00, 0x21, 0x00, 0x01,
		}
	case "tftp":
		// RRQ for "apophis" in octet mode.
		return []byte{0x00, 0x01, 'a', 'p', 'o', 'p', 'h', 'i', 's', 0x00, 'o', 'c', 't', 'e', 't', 0x00}
	case "sip":
		// OPTIONS request to the host.
		return []byte("OPTIONS sip:apophis@apophis SIP/2.0\r\nVia: SIP/2.0/UDP apophis;branch=z9hG4bK\r\nFrom: <sip:probe@apophis>;tag=probe\r\nTo: <sip:apophis>\r\nCall-ID: probe@apophis\r\nCSeq: 1 OPTIONS\r\nMax-Forwards: 0\r\nContent-Length: 0\r\n\r\n")
	}
	return nil
}

func describeUDPResponse(service string, b []byte) string {
	truncated := string(b)
	if len(truncated) > 200 {
		truncated = truncated[:200]
	}
	truncated = strings.Map(func(r rune) rune {
		if r >= 32 && r < 127 || r == '\n' || r == '\r' || r == '\t' {
			return r
		}
		return '.'
	}, truncated)
	switch service {
	case "dns":
		if len(b) >= 12 {
			// Count answers in the response.
			ancount := binary.BigEndian.Uint16(b[6:8])
			return fmt.Sprintf("DNS response ancnt=%d (%d bytes)", ancount, len(b))
		}
	case "ntp":
		if len(b) >= 48 {
			vn := (b[0] >> 3) & 0x07
			mode := b[0] & 0x07
			stratum := int(b[1])
			return fmt.Sprintf("NTP vn=%d mode=%d stratum=%d", vn, mode, stratum)
		}
	case "snmp":
		return fmt.Sprintf("SNMP reply %d bytes", len(b))
	case "sip":
		if i := strings.Index(truncated, "\r\n"); i > 0 {
			return truncated[:i]
		}
	}
	if len(truncated) == 0 {
		return fmt.Sprintf("%s reply %d bytes", service, len(b))
	}
	return fmt.Sprintf("%s reply: %s", service, truncated)
}

// buildSNMPGet returns a minimal SNMPv2c GET request for a single OID. The
// community string is placed verbatim; max length is 32 bytes per RFC 2576.
func buildSNMPGet(community, oid string) []byte {
	if len(community) == 0 {
		community = "public"
	}
	if len(community) > 32 {
		community = community[:32]
	}
	// Encode OID as ASN.1 BER OBJECT IDENTIFIER.
	oidBytes := encodeOID(oid)
	// PDU: GetRequest (0xa0) containing request-id(1=2), error-status(1=2), error-index(1=2), varbindlist(sequence containing one varbind).
	varbind := []byte{
		0x30, byte(len(oidBytes) + 4),
		0x06, byte(len(oidBytes)),
	}
	varbind = append(varbind, oidBytes...)
	varbind = append(varbind, 0x05, 0x00) // NULL value
	pdu := []byte{0xa0, byte(len(varbind) + 12)}
	pdu = append(pdu, 0x02, 0x01, 0x01)         // request-id = 1
	pdu = append(pdu, 0x02, 0x01, 0x00)         // error-status = 0
	pdu = append(pdu, 0x02, 0x01, 0x00)         // error-index = 0
	pdu = append(pdu, 0x30, byte(len(varbind))) // varbind list
	pdu = append(pdu, varbind...)
	// version: 0=SNMPv1, 1=SNMPv2c
	version := []byte{0x02, 0x01, 0x01}
	communityTlv := []byte{0x04, byte(len(community))}
	communityTlv = append(communityTlv, []byte(community)...)
	body := append(version, communityTlv...)
	body = append(body, pdu...)
	msg := []byte{0x30, byte(len(body))}
	msg = append(msg, body...)
	return msg
}

func encodeOID(oid string) []byte {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil
	}
	var first, second int
	fmt.Sscanf(parts[0], "%d", &first)
	fmt.Sscanf(parts[1], "%d", &second)
	out := []byte{byte(first*40 + second)}
	var acc uint32 = 0
	for _, p := range parts[2:] {
		var v uint32
		fmt.Sscanf(p, "%d", &v)
		acc = acc<<7 | (v & 0x7f)
		if v < 128 {
			out = append(out, byte(acc))
			acc = 0
			continue
		}
		// We need to push more bytes for values >= 128. We mark the high
		// bit on all but the last byte. acc holds everything encoded so
		// far; on the next iteration we keep accumulating.
		out = append(out, byte(acc|0x80))
		acc = 0
	}
	// Simple OIDs (<128 per node) — fall back gracefully.
	_ = rand.Int
	return out
}
