// Package snmp performs an unauthenticated SNMPv2c community-string brute
// against UDP/161. We use a curated list of common defaults (public, private,
// manager, monitor, cisco, admin, snmp, secret) and report any successful
// read of sysDescr / sysName / sysContact as a finding. We also fingerprint
// the system via the returned OIDs.
package snmp

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

// Common community strings to test. The list is short by design — we are
// looking for "really bad" defaults, not running a dictionary attack.
var defaults = []string{
	"public", "private", "manager", "monitor", "admin", "snmp", "cisco",
	"secret", "rw", "ro", "trap", "read", "write", "root", "test",
	"cable-docsis", "ILMI", " tivoli", "apc",
}

const portSNMP = 161

// Tester scans UDP/161 for SNMPv2c.
type Tester struct {
	Timeout       time.Duration
	Communities   []string
	MaxConcurrent int
}

func New(t time.Duration) *Tester {
	if t == 0 {
		t = 2 * time.Second
	}
	return &Tester{Timeout: t, Communities: defaults, MaxConcurrent: 16}
}

// Info is the gathered state.
type Info struct {
	Port           int
	Hits           []string // community strings that succeeded
	SysDescr       string
	SysName        string
	SysContact     string
	SysLocation    string
	SysUpTime      string
	NumCommunities int
}

// Audit runs the brute and returns findings.
func (t *Tester) Audit(ctx context.Context, host string, ports []models.PortInfo) ([]models.Finding, *Info) {
	targetPort := portSNMP
	if !portOpen(ports, targetPort) {
		return nil, nil
	}
	info := &Info{Port: targetPort}
	concurrency := t.MaxConcurrent
	if concurrency <= 0 {
		concurrency = 16
	}
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, c := range t.Communities {
		select {
		case <-ctx.Done():
			wg.Wait()
			return t.toFindings(host, info), info
		default:
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(c string) {
			defer wg.Done()
			defer func() { <-sem }()
			sysDescr, sysName, sysContact, sysLoc, uptime, err := t.probe(ctx, host, targetPort, c)
			if err != nil {
				return
			}
			mu.Lock()
			info.Hits = append(info.Hits, c)
			info.NumCommunities++
			if info.SysDescr == "" {
				info.SysDescr = sysDescr
			}
			if info.SysName == "" {
				info.SysName = sysName
			}
			if info.SysContact == "" {
				info.SysContact = sysContact
			}
			if info.SysLocation == "" {
				info.SysLocation = sysLoc
			}
			if info.SysUpTime == "" {
				info.SysUpTime = uptime
			}
			mu.Unlock()
		}(c)
	}
	wg.Wait()
	sort.Strings(info.Hits)
	return t.toFindings(host, info), info
}

func portOpen(ports []models.PortInfo, p int) bool {
	for _, pp := range ports {
		if pp.Port == p {
			return true
		}
	}
	return false
}

// probe sends a single SNMPv2c GET for sysDescr.0 + sysName.0 + sysContact.0
// + sysLocation.0 + sysUpTime.0 and parses the varbind list. Returns the
// strings for each OID if the community was accepted.
func (t *Tester) probe(ctx context.Context, host string, port int, community string) (sysDescr, sysName, sysContact, sysLoc, uptime string, err error) {
	d := net.Dialer{Timeout: t.Timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return "", "", "", "", "", err
	}
	defer conn.Close()
	oids := []string{
		"1.3.6.1.2.1.1.1.0", // sysDescr
		"1.3.6.1.2.1.1.5.0", // sysName
		"1.3.6.1.2.1.1.4.0", // sysContact
		"1.3.6.1.2.1.1.6.0", // sysLocation
		"1.3.6.1.2.1.1.3.0", // sysUpTime
	}
	pkt := buildSNMPGetBulk(community, oids)
	_ = conn.SetWriteDeadline(time.Now().Add(t.Timeout))
	if _, err := conn.Write(pkt); err != nil {
		return "", "", "", "", "", err
	}
	_ = conn.SetReadDeadline(time.Now().Add(t.Timeout))
	buf := make([]byte, 1500)
	n, _ := conn.Read(buf)
	if n < 20 {
		return "", "", "", "", "", fmt.Errorf("no response")
	}
	return parseSNMPResponse(buf[:n])
}

// buildSNMPGetBulk returns an SNMPv2c GetBulkRequest PDU. The PDU is wrapped
// in the SNMP message envelope (version=1, community=community, PDU).
func buildSNMPGetBulk(community string, oids []string) []byte {
	if len(community) > 32 {
		community = community[:32]
	}
	// Build varbind list.
	varbindSeq := []byte{}
	for _, o := range oids {
		varBind := []byte{0x30}
		oidBytes := encodeOIDBER(o)
		varBind = append(varBind, berLen(2+len(oidBytes)+2)...)
		varBind = append(varBind, 0x06, byte(len(oidBytes)))
		varBind = append(varBind, oidBytes...)
		varBind = append(varBind, 0x05, 0x00) // NULL value
		varbindSeq = append(varbindSeq, varBind...)
	}
	// GetBulkRequest PDU: tag 0xa5
	pdu := []byte{0xa5}
	body := []byte{
		0x02, 0x01, 0x01, // request-id = 1
		0x02, 0x01, 0x00, // non-repeaters = 0
		0x02, 0x01, 0x0a, // max-repetitions = 10
		0x30, byte(len(varbindSeq)),
	}
	body = append(body, varbindSeq...)
	pdu = append(pdu, berLen(len(body))...)
	pdu = append(pdu, body...)
	// Message envelope: version (INTEGER 1 = SNMPv2c) + community (OCTET STRING) + PDU
	msg := []byte{
		0x02, 0x01, 0x01, // version = 1 (SNMPv2c)
		0x04, byte(len(community)),
	}
	msg = append(msg, []byte(community)...)
	msg = append(msg, pdu...)
	// Outer SEQUENCE.
	out := []byte{0x30, byte(len(msg))}
	out = append(out, msg...)
	return out
}

func encodeOIDBER(oid string) []byte {
	parts := strings.Split(oid, ".")
	if len(parts) < 2 {
		return nil
	}
	var first, second int
	fmt.Sscanf(parts[0], "%d", &first)
	fmt.Sscanf(parts[1], "%d", &second)
	out := []byte{byte(first*40 + second)}
	for _, p := range parts[2:] {
		var v int
		fmt.Sscanf(p, "%d", &v)
		out = append(out, encodeBase128(v)...)
	}
	return out
}

func encodeBase128(v int) []byte {
	if v < 0 {
		v = 0
	}
	if v < 0x80 {
		return []byte{byte(v)}
	}
	// Compute the byte length.
	var stack [5]byte
	n := 0
	tmp := v
	for tmp > 0 {
		stack[n] = byte(tmp & 0x7f)
		tmp >>= 7
		n++
	}
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = stack[n-1-i]
		if i < n-1 {
			out[i] |= 0x80
		}
	}
	return out
}

func parseSNMPResponse(b []byte) (sysDescr, sysName, sysContact, sysLoc, uptime string, err error) {
	if len(b) < 12 || b[0] != 0x30 {
		return "", "", "", "", "", fmt.Errorf("not snmp")
	}
	// Walk varbinds and pluck the values for known OIDs.
	walk := func(seq []byte) {
		i := 0
		for i < len(seq) {
			if i+2 > len(seq) || seq[i] != 0x30 {
				return
			}
			l, hdr := decodeLen(seq[i+1:])
			end := i + 1 + hdr + l
			if end > len(seq) {
				end = len(seq)
			}
			// Inside each varbind: SEQUENCE(OID, value)
			j := i + 1 + hdr
			if j+2 > end || seq[j] != 0x06 {
				i = end
				continue
			}
			ol, oh := decodeLen(seq[j+1:])
			oidEnd := j + 1 + oh + ol
			if oidEnd > end {
				i = end
				continue
			}
			oid := oidToString(seq[j+1+oh : oidEnd])
			// Value.
			if oidEnd+1 < end {
				tag := seq[oidEnd]
				vl, vh := decodeLen(seq[oidEnd+1:])
				valEnd := oidEnd + 1 + vh + vl
				if valEnd > end {
					valEnd = end
				}
				val := decodeValue(tag, seq[oidEnd+1+vh:valEnd])
				switch oid {
				case "1.3.6.1.2.1.1.1.0":
					sysDescr = val
				case "1.3.6.1.2.1.1.5.0":
					sysName = val
				case "1.3.6.1.2.1.1.4.0":
					sysContact = val
				case "1.3.6.1.2.1.1.6.0":
					sysLoc = val
				case "1.3.6.1.2.1.1.3.0":
					uptime = val
				}
			}
			i = end
		}
	}
	// Skip the message envelope to find the varbind list (SEQUENCE OF).
	// Find PDU: GetResponse = 0xa2
	for i := 0; i < len(b)-2; i++ {
		if b[i] == 0xa2 {
			pl, ph := decodeLen(b[i+1:])
			pdu := b[i+1+ph : i+1+ph+pl]
			// Varbind list is the last SEQUENCE in the PDU.
			walkReverse(pdu, walk)
			return
		}
	}
	return "", "", "", "", "", fmt.Errorf("no pdu")
}

// walkReverse locates the varbind list (last SEQUENCE OF) and feeds it to fn.
func walkReverse(pdu []byte, fn func(seq []byte)) {
	// The varbind list is the final SEQUENCE OF in the PDU. We find the
	// longest trailing SEQUENCE OF.
	for i := len(pdu) - 1; i > 0; i-- {
		if pdu[i] == 0x30 {
			l, hdr := decodeLen(pdu[i+1:])
			if l < 0 || i+1+hdr+l > len(pdu) {
				continue
			}
			fn(pdu[i+1+hdr : i+1+hdr+l])
			return
		}
	}
}

func decodeValue(tag byte, raw []byte) string {
	switch tag {
	case 0x04:
		return string(raw)
	case 0x02:
		if len(raw) == 0 {
			return ""
		}
		var n int64
		for _, b := range raw {
			n = n<<8 | int64(b)
		}
		return fmt.Sprintf("%d", n)
	case 0x06:
		return oidToString(raw)
	case 0x40:
		// IpAddress: 4 octets.
		if len(raw) == 4 {
			return fmt.Sprintf("%d.%d.%d.%d", raw[0], raw[1], raw[2], raw[3])
		}
		return fmt.Sprintf("ip:%x", raw)
	}
	return fmt.Sprintf("tag=0x%02x", tag)
}

func oidToString(b []byte) string {
	if len(b) < 1 {
		return ""
	}
	first := int(b[0])
	out := []string{fmt.Sprintf("%d", first/40), fmt.Sprintf("%d", first%40)}
	var acc uint32
	var have bool
	for _, x := range b[1:] {
		acc = (acc << 7) | uint32(x&0x7f)
		have = true
		if x&0x80 == 0 {
			out = append(out, fmt.Sprintf("%d", acc))
			acc = 0
			have = false
		}
	}
	if have {
		out = append(out, fmt.Sprintf("%d", acc))
	}
	return strings.Join(out, ".")
}

func decodeLen(b []byte) (int, int) {
	if len(b) == 0 {
		return -1, 0
	}
	if b[0] < 0x80 {
		return int(b[0]), 1
	}
	n := int(b[0] & 0x7f)
	if n == 0 || len(b) < 1+n {
		return -1, 1
	}
	v := 0
	for j := 1; j <= n; j++ {
		v = v<<8 | int(b[j])
	}
	return v, 1 + n
}

func berLen(n int) []byte {
	switch {
	case n < 0x80:
		return []byte{byte(n)}
	case n < 0x100:
		return []byte{0x81, byte(n)}
	default:
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
}

func (t *Tester) toFindings(host string, info *Info) []models.Finding {
	f := []models.Finding{}
	if len(info.Hits) == 0 {
		return f
	}
	hits := strings.Join(info.Hits, ", ")
	f = append(f, models.Finding{
		Title:       fmt.Sprintf("SNMP community string brute succeeded on %s:%d", host, info.Port),
		Severity:    models.SeverityHigh,
		Category:    "SNMP",
		Target:      host,
		Port:        info.Port,
		Evidence:    fmt.Sprintf("community=[%s]; sysDescr=%q sysName=%q sysContact=%q sysLocation=%q sysUpTime=%s", hits, info.SysDescr, info.SysName, info.SysContact, info.SysLocation, info.SysUpTime),
		Description: "The SNMP service accepted one or more default community strings. With read access an attacker can enumerate the routing table, ARP cache, interface counters, installed software and (if the device supports it) the full configuration. With write-capable communities like 'private' they can rewrite configs, change routing, or disable the device.",
		Exploit:     "snmpwalk -v2c -c <community> <target> 1.3.6.1; onesixtyone -c community.txt <target>",
		Remediation: "Replace community strings with SNMPv3 (authPriv) or remove the service entirely if not needed. Move SNMP off UDP/161 to a dedicated management VLAN.",
		References:  []string{"https://www.tenable.com/blog/managing-snmp-community-strings-for-security"},
		Tags:        []string{"snmp", "default-creds", "info-disclosure"},
	})
	if info.SysDescr != "" {
		f = append(f, models.Finding{
			Title:       fmt.Sprintf("SNMP system description disclosure on %s:%d", host, info.Port),
			Severity:    models.SeverityInfo,
			Category:    "SNMP",
			Target:      host,
			Port:        info.Port,
			Evidence:    info.SysDescr,
			Description: "The SNMP sysDescr.0 leaks the OS and version. Use to focus exploit selection (e.g. Cisco IOS 12.4, Linux 4.15, ArubaOS).",
			Exploit:     "Search the disclosed string against apophis_check_cve.",
			Remediation: "Restrict SNMP via ACLs; use SNMPv3 with auth + priv.",
			Tags:        []string{"snmp", "disclosure"},
		})
	}
	return f
}

// suppress unused-import warning when stripping debug code.
var _ = binary.BigEndian
