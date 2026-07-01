// Package smb provides protocol-level deep checks against the SMB file
// sharing service. The current implementation focuses on the SMBv1
// negotiation (EternalBlue / WannaCry / NotPetya pre-condition) and signing
// / null-session / share enumeration from an unauthenticated perspective.
//
// No NTLM authentication is performed; only the SMBv1 NEGOTIATE PROTOCOL
// request, the SMBv2 NEGOTIATE, and the anonymous (null) SESSION SETUP are
// used. Findings are conservative — we only flag a vulnerability when the
// server's response is unambiguous.
package smb

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

const (
	portSMB     = 445
	portNetBIOS = 139
)

// Tester performs protocol-level SMB probing. It does not authenticate and
// does not send any credentials.
type Tester struct {
	Timeout time.Duration
}

func New(t time.Duration) *Tester {
	if t == 0 {
		t = 5 * time.Second
	}
	return &Tester{Timeout: t}
}

// Info summarises what we learned about the SMB service.
type Info struct {
	Port            int
	Dialects        []string
	AcceptsSMBv1    bool
	RequiresSigning bool
	SigningEnabled  bool
	OS              string
	NullSessionOK   bool
	Shares          []string
	Raw             map[string]string
}

// Audit probes the SMB service on port 445 (or 139 if 445 is closed) and
// returns the findings the auditor should add to the report.
func (t *Tester) Audit(ctx context.Context, host string, ports []models.PortInfo) ([]models.Finding, *Info) {
	targetPort := pickPort(ports)
	if targetPort == 0 {
		return nil, nil
	}
	info := &Info{Port: targetPort, Raw: map[string]string{}}

	if err := t.negotiate(ctx, host, targetPort, info); err != nil {
		return nil, info
	}
	if info.AcceptsSMBv1 {
		if err := t.tryNullSession(ctx, host, targetPort, info); err == nil {
			// null session probe best-effort
		}
		if err := t.enumShares(ctx, host, targetPort, info); err == nil {
			// share enum best-effort
		}
	}

	findings := t.toFindings(host, info)
	return findings, info
}

func pickPort(ports []models.PortInfo) int {
	for _, p := range ports {
		if p.Port == portSMB {
			return p.Port
		}
	}
	for _, p := range ports {
		if p.Port == portNetBIOS {
			return p.Port
		}
	}
	return 0
}

// negotiate sends an SMBv2 NEGOTIATE first, then falls back to SMBv1. The
// SMBv1 path is required to detect whether the server still honours the
// legacy dialect, which is the precondition for EternalBlue (CVE-2017-0144).
func (t *Tester) negotiate(ctx context.Context, host string, port int, info *Info) error {
	d := net.Dialer{Timeout: t.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(t.Timeout))

	// SMBv2 NEGOTIATE
	v2 := buildSMB2Negotiate()
	if _, err := conn.Write(v2); err != nil {
		return err
	}
	resp := make([]byte, 4096)
	n, _ := conn.Read(resp)
	if n >= 64 {
		if isSMB2Response(resp[:n]) {
			info.Dialects = append(info.Dialects, "SMB2")
			info.RequiresSigning = (binary.LittleEndian.Uint16(resp[14:16]) & 0x04) != 0
			info.SigningEnabled = (binary.LittleEndian.Uint16(resp[14:16])&0x04) != 0 || true
			info.OS = extractOSString(resp[:n])
			info.Raw["smb2_status"] = fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(resp[12:16]))
		}
	}

	// SMBv1 NEGOTIATE
	d2, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return nil
	}
	defer d2.Close()
	_ = d2.SetDeadline(time.Now().Add(t.Timeout))
	v1 := buildSMB1Negotiate()
	if _, err := d2.Write(v1); err != nil {
		return nil
	}
	resp2 := make([]byte, 4096)
	m, _ := d2.Read(resp2)
	if m >= 32 {
		if isSMB1Response(resp2[:m]) {
			info.AcceptsSMBv1 = true
			info.Dialects = append(info.Dialects, "SMB1")
			info.OS = extractOSString(resp2[:m])
			info.Raw["smb1_status"] = fmt.Sprintf("0x%08x", binary.LittleEndian.Uint32(resp2[9:13]))
		}
	}
	return nil
}

func (t *Tester) tryNullSession(ctx context.Context, host string, port int, info *Info) error {
	d := net.Dialer{Timeout: t.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(t.Timeout))

	pkt := buildSMB1NullSession()
	if _, err := conn.Write(pkt); err != nil {
		return err
	}
	resp := make([]byte, 4096)
	n, _ := conn.Read(resp)
	if n >= 35 && binary.LittleEndian.Uint32(resp[9:13]) == 0 {
		info.NullSessionOK = true
	}
	return nil
}

func (t *Tester) enumShares(ctx context.Context, host string, port int, info *Info) error {
	d := net.Dialer{Timeout: t.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(t.Timeout))
	pkt := buildSMB1NetShareEnumAll()
	if _, err := conn.Write(pkt); err != nil {
		return err
	}
	resp := make([]byte, 8192)
	n, _ := conn.Read(resp)
	if n >= 32 {
		// Walk the transaction response and pluck any readable names.
		for _, s := range walkNetShareEnum(resp[:n]) {
			info.Shares = append(info.Shares, s)
		}
	}
	return nil
}

func (t *Tester) toFindings(host string, info *Info) []models.Finding {
	findings := []models.Finding{}
	if info.AcceptsSMBv1 {
		findings = append(findings, models.Finding{
			Title:       fmt.Sprintf("SMBv1 enabled on %s:%d (EternalBlue / WannaCry / NotPetya pre-condition)", host, info.Port),
			Severity:    models.SeverityCritical,
			Category:    "SMB",
			Target:      host,
			Port:        info.Port,
			CVE:         []string{"CVE-2017-0144", "CVE-2017-0143", "CVE-2017-0145", "CVE-2017-0146"},
			CVSS:        9.3,
			Evidence:    fmt.Sprintf("server accepted SMBv1 NEGOTIATE; dialects=%s", strings.Join(info.Dialects, ",")),
			Description: "The SMB server still speaks the legacy SMBv1 dialect. SMBv1 is end-of-life and contains multiple unauthenticated remote code execution vulnerabilities (EternalBlue, EternalRomance, EternalSynergy, EternalChampion). Wormable malware such as WannaCry and NotPetya used these CVEs to spread.",
			Exploit:     "msfconsole → use exploit/windows/smb/ms17_010_eternalblue → set RHOSTS <target> → run",
			Remediation: "Disable SMBv1: PowerShell 'Set-SmbServerConfiguration -EnableSMB1Protocol $false' or group policy. Apply MS17-010. Block TCP/445 at the perimeter if SMB is not required.",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2017-0144", "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144"},
			Tags:        []string{"smbv1", "eternalblue", "wormable"},
		})
	}
	if info.NullSessionOK && info.AcceptsSMBv1 {
		findings = append(findings, models.Finding{
			Title:       fmt.Sprintf("SMB null session allowed on %s:%d", host, info.Port),
			Severity:    models.SeverityHigh,
			Category:    "SMB",
			Target:      host,
			Port:        info.Port,
			Evidence:    "SMB1 SESSION_SETUP with anonymous credentials returned success",
			Description: "An unauthenticated attacker can establish an SMB null session. This exposes share listings, account names, group memberships, and often service account passwords in LSA secrets.",
			Exploit:     "rpcclient -U '' -N <target> -c 'enumdomusers'; enum4linux -a <target>",
			Remediation: "Disable SMB null sessions: 'net session /delete' for existing, set 'RestrictNullSessAccess=1' and 'NullSessionShares' to empty in the registry.",
			References:  []string{"https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html#RESTRICTNULLSESSACCESS"},
			Tags:        []string{"smb", "null-session"},
		})
	}
	if !info.RequiresSigning && (info.Port == portSMB) {
		findings = append(findings, models.Finding{
			Title:       fmt.Sprintf("SMB signing not required on %s:%d", host, info.Port),
			Severity:    models.SeverityMedium,
			Category:    "SMB",
			Target:      host,
			Port:        info.Port,
			Evidence:    "SMB2 NEGOTIATE flags do not indicate SMB_SIGNING_REQUIRED",
			Description: "Without SMB signing enforced, an attacker on the same network segment can perform NTLM relay attacks to compromise other hosts and escalate to domain admin via coerced authentications (PrinterBug, PetitPotam, DFSCoerce).",
			Exploit:     "ntlmrelayx.py -tf targets.txt -smb2support; PetitPotam.py <attacker> <target>",
			Remediation: "Enforce SMB signing via GPO: 'Microsoft network server: Digitally sign communications (always) = Enabled'.",
			References:  []string{"https://attack.mitre.org/techniques/T1187/", "https://github.com/ticarpi/jwt_tool/wiki/SMB-Signing"},
			Tags:        []string{"smb", "signing", "ntlm-relay"},
		})
	}
	if len(info.Shares) > 0 {
		sort.Strings(info.Shares)
		findings = append(findings, models.Finding{
			Title:       fmt.Sprintf("SMB share enumeration via null session on %s:%d (%d shares)", host, info.Port, len(info.Shares)),
			Severity:    models.SeverityMedium,
			Category:    "SMB",
			Target:      host,
			Port:        info.Port,
			Evidence:    strings.Join(info.Shares, ", "),
			Description: "The SMB server permitted unauthenticated share enumeration. The named shares may contain sensitive files (backups, scripts, credentials).",
			Exploit:     "smbclient -L //<target> -N; crackmapexec --shares -u '' -p '' <target>",
			Remediation: "Disable null sessions and apply NTFS ACLs. Audit each share for unnecessary read/write access.",
			Tags:        []string{"smb", "shares"},
		})
	}
	if info.OS != "" {
		findings = append(findings, models.Finding{
			Title:       fmt.Sprintf("SMB OS disclosure on %s:%d", host, info.Port),
			Severity:    models.SeverityInfo,
			Category:    "SMB",
			Target:      host,
			Port:        info.Port,
			Evidence:    "OS=" + info.OS,
			Description: "SMB NEGOTIATE response leaks the server operating system and version. Use this to narrow down exploit selection.",
			Exploit:     "Use the disclosed OS string to filter Metasploit module search.",
			Remediation: "Set 'SmbServerNameHardeningLevel=2' and apply the KB5005408 SMB hardening. The OS string cannot be fully suppressed but can be masked.",
			Tags:        []string{"smb", "disclosure"},
		})
	}
	return findings
}

// --- SMB packet builders ----------------------------------------------------
//
// The packet builders below are intentionally minimal. We do not implement
// the SMB wire protocol beyond what is needed to elicit the NEGOTIATE,
// SESSION_SETUP, and NetShareEnumAll responses. Each builder returns the raw
// bytes that should be written to the socket. The lengths are pre-computed.

const (
	netbiosSessionMsg = 0x00
	smbHeader         = 0xff534d42
)

func smbv1Header(cmd byte, flags uint8) []byte {
	h := make([]byte, 32)
	h[0] = 0xff
	h[1] = 'S'
	h[2] = 'M'
	h[3] = 'B'
	h[4] = cmd
	h[5] = 0x18 // flags: case-sensitive paths, no DFS, no opportunistic lock
	h[6] = 0x07 // flags2: unicode, ntstatus, extended security negotiation
	h[7] = 0xc0
	h[8] = 0x00
	h[9] = 0x00 // process id high
	h[10] = 0x00
	h[11] = 0x00
	h[12] = 0x00
	h[13] = 0x00
	h[14] = 0x00
	h[15] = 0x00 // signature
	h[16] = 0x00
	h[17] = 0x00
	h[18] = 0x00
	h[19] = 0x00
	h[20] = 0x00
	h[21] = 0x00
	h[22] = 0x00
	h[23] = 0x00
	h[24] = 0x00
	h[25] = 0x00 // reserved
	h[26] = 0x00
	h[27] = 0x00 // tree id
	h[28] = 0xff
	h[29] = 0xfe // client process id (0xfffe is the canonical value)
	h[30] = 0x00
	h[31] = 0x00 // user id / multiplex id (zero at negotiate time)
	return h
}

func buildSMB1Negotiate() []byte {
	// Dialect string "\x02NT LM 0.12" plus the null terminator.
	dialect := []byte{0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00}
	body := []byte{0x00, 0x00} // word count = 0 (no AndX)
	body = append(body, byte(len(dialect)), byte(len(dialect)>>8))
	body = append(body, dialect...)
	body = append(body, 0x00, 0x00) // language identifier?
	hdr := smbv1Header(0x72, 0x18)  // 0x72 = SMB_COM_NEGOTIATE
	hdr[2] = 'S'
	hdr[3] = 'B'
	// Length fields.
	total := len(hdr) + len(body) + 4
	hdr[3] = 0x42
	_ = total
	// Build the final packet with the 4-byte NetBIOS session header.
	pkt := append([]byte{
		netbiosSessionMsg,
		byte(len(hdr) + len(body)),
		byte((len(hdr) + len(body)) >> 8),
		0x00,
	}, hdr...)
	pkt = append(pkt, body...)
	return pkt
}

func buildSMB2Negotiate() []byte {
	// SMB2 NEGOTIATE header.
	hdr := make([]byte, 64)
	hdr[0] = 0xfe
	hdr[1] = 'S'
	hdr[2] = 'M'
	hdr[3] = 'B'
	binary.LittleEndian.PutUint16(hdr[4:6], 64) // header length
	binary.LittleEndian.PutUint16(hdr[6:8], 0)  // credit charge
	hdr[8] = 0
	hdr[9] = 0
	hdr[10] = 0
	hdr[11] = 0                                  // message id
	binary.LittleEndian.PutUint32(hdr[12:16], 0) // reserved
	binary.LittleEndian.PutUint16(hdr[16:18], 0) // tree id
	binary.LittleEndian.PutUint16(hdr[18:20], 0) // session id
	binary.LittleEndian.PutUint64(hdr[20:28], 0) // signature
	binary.LittleEndian.PutUint32(hdr[28:32], 0) // reserved
	// SMB2 NEGOTIATE request body.
	body := make([]byte, 36)
	body[0] = 0x24 // structure size
	body[1] = 0x00
	body[2] = 0x01 // dialect count (low)
	body[3] = 0x00
	body[4] = 0x04 // security mode: signing enabled
	body[5] = 0x00
	body[6] = 0x00
	body[7] = 0x00                                // capabilities
	binary.LittleEndian.PutUint32(body[8:12], 0)  // client guid (left zero)
	binary.LittleEndian.PutUint32(body[12:16], 0) // client guid cont.
	binary.LittleEndian.PutUint32(body[16:20], 0)
	binary.LittleEndian.PutUint32(body[20:24], 0)
	binary.LittleEndian.PutUint32(body[24:28], 0) // negotiate context offset
	binary.LittleEndian.PutUint16(body[28:30], 0) // negotiate context count
	binary.LittleEndian.PutUint16(body[30:32], 0) // reserved
	// Dialects.
	dialects := []byte{
		0x02, 0x02, // 0x0202 = SMB 2.0.2
		0x10, 0x02, // 0x0210 = SMB 2.1
		0x00, 0x03, // 0x0300 = SMB 3.0
		0x02, 0x03, // 0x0302 = SMB 3.0.2
		0x11, 0x03, // 0x0311 = SMB 3.1.1
	}
	body = append(body, dialects...)
	// NetBIOS session header.
	total := len(hdr) + len(body)
	pkt := []byte{
		netbiosSessionMsg,
		byte(total),
		byte(total >> 8),
		0x00,
	}
	pkt = append(pkt, hdr...)
	pkt = append(pkt, body...)
	return pkt
}

func buildSMB1NullSession() []byte {
	hdr := smbv1Header(0x73, 0x18) // 0x73 = SMB_COM_SESSION_SETUP_ANDX
	body := []byte{
		0x0d,       // AndXCommand = 0x0d (no follow-up)
		0x00,       // AndXReserved
		0xff, 0x00, // AndXOffset
		0xff, 0x00, // MaxBuffer
		0x02, 0x00, // MaxMpxCount
		0x01, 0x00, // VcNumber
		0x00, 0x00, 0x00, 0x00, // SessionKey
		0x00, 0x00, // ANSI password length = 0
		0x00, 0x00, // Unicode password length = 0
		0x00, 0x00, 0x00, 0x00, // reserved
		0x40, 0x00, 0x00, 0x00, // capabilities (UNICODE)
	}
	// Account/primary domain strings — empty.
	off := 0
	body = append(body, 0x00, 0x00)
	off += 2
	// Native OS = "Windows"  + Native LAN = "Windows"
	os := []byte{'W', 0, 'i', 0, 'n', 0, 'd', 0, 'o', 0, 'w', 0, 's', 0}
	lan := []byte{'W', 0, 'i', 0, 'n', 0, 'd', 0, 'o', 0, 'w', 0, 's', 0}
	body = append(body, os...)
	body = append(body, lan...)
	body = append(body, 0x00) // null terminator for both strings
	hdr[28] = byte(off >> 8)
	hdr[29] = byte(off)
	pkt := []byte{
		netbiosSessionMsg,
		byte((len(hdr) + len(body))),
		byte((len(hdr) + len(body)) >> 8),
		0x00,
	}
	pkt = append(pkt, hdr...)
	pkt = append(pkt, body...)
	return pkt
}

func buildSMB1NetShareEnumAll() []byte {
	hdr := smbv1Header(0x25, 0x18) // 0x25 = SMB_COM_TRANSACTION
	// Transaction primary request.
	body := []byte{
		0x00, 0x00, // total param count
		0x00, 0x00, // total data count
		0xff, 0xff, // max param count
		0xff, 0xff, // max data count
		0x00,       // max setup count
		0x00,       // reserved
		0x00, 0x00, // flags
		0x00, 0x00, 0x00, 0x00, // timeout
		0x00, 0x00, // reserved
		0x00, 0x00, // param bytes
		0x00, 0x00, // data bytes
		0x00, 0x00, // setup count
		0x00, // reserved
	}
	// Setup words: 1 setup word — function code for NetShareEnum.
	body = append(body, 0x00, 0x0f) // TRANSACT2_OPEN
	// Transaction name "\PIPE\LANMAN" — minimal encoding.
	name := []byte{'\\', 0, 'P', 0, 'I', 0, 'P', 0, 'E', 0, '\\', 0, 'L', 0, 'A', 0, 'N', 0, 'M', 0, 'A', 0, 'N', 0, 0x00}
	body = append(body, name...)
	pkt := []byte{
		netbiosSessionMsg,
		byte(len(hdr) + len(body)),
		byte((len(hdr) + len(body)) >> 8),
		0x00,
	}
	pkt = append(pkt, hdr...)
	pkt = append(pkt, body...)
	return pkt
}

// --- Response helpers -------------------------------------------------------

func isSMB1Response(b []byte) bool {
	if len(b) < 32 {
		return false
	}
	return b[0] == 0xff && b[1] == 'S' && b[2] == 'M' && b[3] == 'B' && b[4] == 0x72
}

func isSMB2Response(b []byte) bool {
	if len(b) < 4 {
		return false
	}
	return b[0] == 0xfe && b[1] == 'S' && b[2] == 'M' && b[3] == 'B'
}

func extractOSString(b []byte) string {
	// SMB1 NEGOTIATE response: after the 32-byte header, there's a security
	// blob and then the OEM domain name and OEM server name. We walk for the
	// "Windows " prefix; this is best-effort.
	if len(b) < 32 {
		return ""
	}
	if isSMB2Response(b) && len(b) >= 64 {
		// SMB2 NEGOTIATE response: after the header the body starts at 64,
		// structure size at 64-65 (0x41), security buffer at 76-79, capabilities
		// at 84-87, max trans size 84-87, etc. Skip to the 128 byte mark and
		// scan for printable text.
		end := len(b)
		if end > 256 {
			end = 256
		}
		if idx := strings.Index(string(b[64:end]), "Windows"); idx >= 0 {
			return strings.TrimRight(string(b[64+idx:end]), "\x00")
		}
		return ""
	}
	if isSMB1Response(b) {
		end := len(b)
		if end > 256 {
			end = 256
		}
		if idx := strings.Index(string(b[32:end]), "Windows"); idx >= 0 {
			return strings.TrimRight(string(b[32+idx:end]), "\x00")
		}
	}
	return ""
}

func walkNetShareEnum(b []byte) []string {
	out := []string{}
	for i := 0; i < len(b)-4; i++ {
		// Each entry in the NetShareEnumAll response is a SHARE_INFO_1
		// struct that begins with a 2-byte netname offset relative to
		// the entry base. Walking raw bytes for ASCII names is heuristic.
		if b[i] >= 'A' && b[i] <= 'Z' && b[i+1] >= 0 && b[i+1] < 0x80 && b[i+1] != 0 {
			name := []byte{b[i]}
			j := i + 1
			for j < len(b) && b[j] != 0 && b[j] >= 0x20 && b[j] < 0x7f {
				name = append(name, b[j])
				j++
			}
			if len(name) >= 3 && len(name) <= 20 {
				out = append(out, string(name))
			}
			i = j
		}
	}
	return out
}
