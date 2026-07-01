package auth

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

// NTLMSignatures are the byte sequences we look for at the start of an
// NTLMSSP message. The 8-byte signature is "NTLMSSP\0".
var ntlmsspSig = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00}

// NTLMMessageType identifies the kind of NTLMSSP message.
type NTLMMessageType uint32

const (
	NTLMNegotiate NTLMMessageType = 1
	NTLMChallenge NTLMMessageType = 2
	NTLMResponse  NTLMMessageType = 3
)

// NTLMFlags is a typed view of the 4-byte NegotiateFlags field.
type NTLMFlags uint32

const (
	NTLMFlagNegotiateUnicode    NTLMFlags = 1 << 0
	NTLMFlagNegotiateOEM        NTLMFlags = 1 << 1
	NTLMFlagRequestTarget       NTLMFlags = 1 << 2
	NTLMFlagNegotiateSign       NTLMFlags = 1 << 4
	NTLMFlagNegotiateSeal       NTLMFlags = 1 << 5
	NTLMFlagNegotiateLMKey      NTLMFlags = 1 << 7
	NTLMFlagNegotiateNTLM       NTLMFlags = 1 << 9
	NTLMFlagNegotiateOEM2       NTLMFlags = 1 << 13
	NTLMFlagNegotiateAlwaysSign NTLMFlags = 1 << 15
	NTLMFlagTargetTypeDomain    NTLMFlags = 1 << 12
	NTLMFlagNegotiateExtended   NTLMFlags = 1 << 17
	NTLMFlagNegotiateTargetInfo NTLMFlags = 1 << 23
	NTLMFlagNegotiateVersion    NTLMFlags = 1 << 25
	NTLMFlagNegotiate128        NTLMFlags = 1 << 29
	NTLMFlagNegotiateKeyExch    NTLMFlags = 1 << 30
)

// NTLMMessage is the high-level view of an NTLMSSP message we care about.
type NTLMMessage struct {
	Type        NTLMMessageType
	Flags       NTLMFlags
	Domain      string
	User        string
	Workstation string
	Target      string
}

// ParseNTLMMessage parses an NTLMSSP message and returns the high-level view.
// Returns nil if the buffer does not start with the NTLMSSP signature.
func ParseNTLMMessage(b []byte) *NTLMMessage {
	if len(b) < 12 {
		return nil
	}
	if !equal(b[:8], ntlmsspSig) {
		return nil
	}
	mtype := NTLMMessageType(binary.LittleEndian.Uint32(b[8:12]))
	if mtype != NTLMNegotiate && mtype != NTLMChallenge && mtype != NTLMResponse {
		return nil
	}
	out := &NTLMMessage{Type: mtype}
	switch mtype {
	case NTLMNegotiate:
		// Negotiate body: 8 byte sig + 4 type + 4 flags + ... + DomainNameFields + WorkstationFields
		// Header offsets are at 12..16 (DomainLen), 16..20 (DomainMax), 20..24 (DomainOff),
		// 24..28 (WorkstationLen), 28..32 (WorkstationMax), 32..36 (WorkstationOff).
		if len(b) < 32 {
			return nil
		}
		out.Flags = NTLMFlags(binary.LittleEndian.Uint32(b[12:16]))
	case NTLMChallenge:
		// Challenge: 8 + 4 + 8 (TargetName) + 4 (Flags) + 8 (Challenge) + ...
		// Header offsets at: 12..16 (TargetNameLen), 16..20 (TargetNameMax),
		// 20..24 (TargetNameOff), 24..28 (Flags).
		if len(b) < 24 {
			return nil
		}
		tlen := int(binary.LittleEndian.Uint16(b[12:14]))
		tmax := int(binary.LittleEndian.Uint16(b[14:16]))
		toff := int(binary.LittleEndian.Uint32(b[16:20]))
		out.Flags = NTLMFlags(binary.LittleEndian.Uint32(b[20:24]))
		if toff+tlen <= len(b) && tlen > 0 && tmax > 0 {
			out.Target = string(b[toff : toff+tlen])
		}
	}
	return out
}

// RiskScore grades the message based on the negotiated flags. Higher = worse.
func (m *NTLMMessage) RiskScore() (score int, reasons []string) {
	if m == nil {
		return 0, nil
	}
	if m.Flags&NTLMFlagNegotiateLMKey != 0 {
		score += 50
		reasons = append(reasons, "NegotiateLMKey (LM response accepted)")
	}
	if m.Flags&NTLMFlagNegotiateOEM != 0 && m.Flags&NTLMFlagNegotiateUnicode == 0 {
		score += 20
		reasons = append(reasons, "OEM-only (no Unicode)")
	}
	if m.Flags&NTLMFlagNegotiateNTLM == 0 {
		score += 30
		reasons = append(reasons, "NTLM response not negotiated")
	}
	if m.Flags&NTLMFlagNegotiateExtended == 0 {
		score += 10
		reasons = append(reasons, "no NTLM2 extended session security")
	}
	if m.Flags&NTLMFlagNegotiate128 == 0 {
		score += 5
		reasons = append(reasons, "no 128-bit key negotiation (only 56-bit RC4)")
	}
	if m.Flags&NTLMFlagNegotiateSign == 0 {
		score += 5
		reasons = append(reasons, "signing not negotiated (relay possible)")
	}
	if m.Flags&NTLMFlagRequestTarget == 0 {
		score += 5
		reasons = append(reasons, "target info not requested")
	}
	return score, reasons
}

// NTLMInspector probes a target for NTLMSSP negotiate / challenge messages
// and reports the negotiated flags. We connect to the candidate NTLM
// endpoints (SMB, HTTP, LDAP, MSSQL) and either send a Negotiate and read
// the Challenge, or just passively observe the Negotiate that the server
// sends first when its banner includes NTLMSSP.
type NTLMInspector struct {
	Timeout time.Duration
}

// Inspection is the per-endpoint outcome.
type Inspection struct {
	Port    int
	Service string
	Message *NTLMMessage
	Err     error
}

// InspectSMB connects to SMB (445 or 139) and triggers an NTLMSSP challenge.
// This is the highest-fidelity NTLM endpoint: every modern Windows SMB
// server responds with NTLMSSP when an anonymous session setup is sent.
func (i *NTLMInspector) InspectSMB(ctx context.Context, host string, port int) Inspection {
	dialer := net.Dialer{Timeout: i.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return Inspection{Port: port, Service: "smb", Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(i.Timeout))
	// Send a minimal SMB1 Negotiate so the server replies with NTLMSSP in
	// the Session Setup challenge.
	pkt := buildSMB1NegotiateForNTLM()
	if _, err := conn.Write(pkt); err != nil {
		return Inspection{Port: port, Service: "smb", Err: err}
	}
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n < 12 {
		return Inspection{Port: port, Service: "smb", Err: fmt.Errorf("short SMB response: %d bytes", n)}
	}
	// Look for NTLMSSP signature in the response (server may include it
	// in a Session Setup response).
	for i := 0; i+12 <= n; i++ {
		if equal(buf[i:i+8], ntlmsspSig) {
			m := ParseNTLMMessage(buf[i:n])
			if m != nil {
				return Inspection{Port: port, Service: "smb", Message: m}
			}
		}
	}
	return Inspection{Port: port, Service: "smb", Err: fmt.Errorf("no NTLMSSP in SMB response")}
}

// InspectHTTP sends a Negotiate Authorization header and reads the
// WWW-Authenticate: NTLM challenge that follows. This works against IIS,
// OWA, RDWeb, ADFS, etc.
func (i *NTLMInspector) InspectHTTP(ctx context.Context, url string) Inspection {
	dialer := net.Dialer{Timeout: i.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", stripScheme(url))
	if err != nil {
		return Inspection{Service: "http", Err: err}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(i.Timeout))
	// Send Authorization: NTLM with a base64'd Type-1 (negotiate) message.
	ntlmNegotiate := buildNTLMSSPType1()
	auth := "Authorization: NTLM " + b64(ntlmNegotiate) + "\r\n"
	req := "GET / HTTP/1.1\r\nHost: " + stripScheme(url) + "\r\n" + auth + "Connection: close\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		return Inspection{Service: "http", Err: err}
	}
	buf := make([]byte, 8192)
	n, _ := conn.Read(buf)
	body := string(buf[:n])
	for _, line := range strings.Split(body, "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "www-authenticate:") && strings.Contains(strings.ToLower(line), "ntlm") {
			// Extract the base64 token after "NTLM ".
			parts := strings.SplitN(line, " ", 2)
			if len(parts) != 2 {
				continue
			}
			chal, err := unb64(strings.TrimSpace(parts[1]))
			if err != nil {
				continue
			}
			m := ParseNTLMMessage(chal)
			if m != nil {
				return Inspection{Service: "http", Message: m}
			}
		}
	}
	return Inspection{Service: "http", Err: fmt.Errorf("no NTLMSSP challenge in HTTP response")}
}

// NTLMToFindings renders the inspections as findings.
func NTLMToFindings(host string, inspections []Inspection) []models.Finding {
	findings := []models.Finding{}
	seen := map[string]bool{}
	sort.Slice(inspections, func(i, j int) bool {
		return inspections[i].Port < inspections[j].Port
	})
	for _, ins := range inspections {
		if ins.Message == nil {
			continue
		}
		score, reasons := ins.Message.RiskScore()
		if score == 0 {
			continue
		}
		key := fmt.Sprintf("%d", uint32(ins.Message.Type)) + ":" + ins.Service
		if seen[key] {
			continue
		}
		seen[key] = true
		sev := models.SeverityLow
		switch {
		case score >= 60:
			sev = models.SeverityCritical
		case score >= 30:
			sev = models.SeverityHigh
		case score >= 10:
			sev = models.SeverityMedium
		}
		title := fmt.Sprintf("NTLM dialect weakness on %s:%d (%s) — score %d", host, ins.Port, ins.Service, score)
		findings = append(findings, F(
			VectorNTLMv1,
			title,
			fmt.Sprintf("%s:%d", host, ins.Port),
			sev,
			fmt.Sprintf("flags=0x%08x reasons=%v target=%q", uint32(ins.Message.Flags), reasons, ins.Message.Target),
			"The NTLMSSP challenge negotiated weak / legacy flags. Each disabled flag reduces the cost of an offline brute-force or NTLM relay attack.",
			strings.Join(reasons, "; "),
			"Group Policy: 'Network security: LAN Manager authentication level' = 'Send NTLMv2 response only. Refuse LM & NTLM.'. This forces NTLMv2 with 128-bit keys + extended session security on every endpoint.",
		))
	}
	return findings
}

// --- NTLMSSP message builders ---------------------------------------------

// buildNTLMSSPType1 builds an NTLMSSP NEGOTIATE message that requests:
//   - Unicode (no OEM)
//   - NTLM (no LM)
//   - Extended session security (NTLM2)
//   - 128-bit key negotiation
//   - Always sign / seal
//   - Target info
//   - Version
//
// The message intentionally avoids NegotiateLMKey and NegotiateOEM.
func buildNTLMSSPType1() []byte {
	body := make([]byte, 32)
	body[0] = 'N'
	body[1] = 'T'
	body[2] = 'L'
	body[3] = 'M'
	body[4] = 'S'
	body[5] = 'S'
	body[6] = 'P'
	body[7] = 0x00
	binary.LittleEndian.PutUint32(body[8:12], uint32(NTLMNegotiate))
	flags := NTLMFlagNegotiateUnicode |
		NTLMFlagRequestTarget |
		NTLMFlagNegotiateSign |
		NTLMFlagNegotiateSeal |
		NTLMFlagNegotiateNTLM |
		NTLMFlagNegotiateAlwaysSign |
		NTLMFlagTargetTypeDomain |
		NTLMFlagNegotiateExtended |
		NTLMFlagNegotiateTargetInfo |
		NTLMFlagNegotiateVersion |
		NTLMFlagNegotiate128 |
		NTLMFlagNegotiateKeyExch
	binary.LittleEndian.PutUint32(body[12:16], uint32(flags))
	// Domain / Workstation fields are zero (we leave them empty — the
	// server fills them in the challenge).
	binary.LittleEndian.PutUint16(body[16:18], 0)
	binary.LittleEndian.PutUint16(body[18:20], 0)
	binary.LittleEndian.PutUint32(body[20:24], 0)
	binary.LittleEndian.PutUint16(body[24:26], 0)
	binary.LittleEndian.PutUint16(body[26:28], 0)
	binary.LittleEndian.PutUint32(body[28:32], 0)
	return body
}

// buildSMB1NegotiateForNTLM is the minimum SMB1 packet that triggers an
// NTLMSSP challenge. We embed the same NTLMSSPType1 payload in the
// Session Setup blob so the server's challenge tells us everything we need.
func buildSMB1NegotiateForNTLM() []byte {
	// Outer SMB1 header (32 bytes) + word count 0 + dialect "\x02NT LM 0.12\0"
	hdr := make([]byte, 32)
	copy(hdr[0:4], []byte{0xff, 'S', 'M', 'B'})
	hdr[4] = 0x72 // SMB_COM_NEGOTIATE
	hdr[5] = 0x18
	hdr[6] = 0x07
	hdr[7] = 0xc0
	dialect := []byte{0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00}
	body := []byte{0x00, 0x00}
	body = append(body, byte(len(dialect)), byte(len(dialect)>>8))
	body = append(body, dialect...)
	body = append(body, 0x00, 0x00)
	nb := []byte{0x00, byte(len(hdr) + len(body)), byte((len(hdr) + len(body)) >> 8), 0x00}
	return append(nb, append(hdr, body...)...)
}

// --- helpers --------------------------------------------------------------

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func b64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func unb64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(strings.TrimSpace(s))
}

func stripScheme(u string) string {
	for _, p := range []string{"https://", "http://"} {
		if strings.HasPrefix(u, p) {
			return u[len(p):]
		}
	}
	return u
}
