package mcp

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

// net_dialer returns a *net.Dialer with the given per-probe timeout. Wrapped
// here so the MCP handler doesn't pull in "net" directly.
func net_dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout}
}

// tcpProbe is the helper used by every deep-protocol probe: it tries to
// connect to the given port and returns a one-element PortInfo slice when
// the port is open, nil otherwise.
func tcpProbe(ctx context.Context, d *net.Dialer, host string, port int) []models.PortInfo {
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil
	}
	conn.Close()
	return []models.PortInfo{{
		Port:     port,
		Protocol: "tcp",
		State:    "open",
		Service:  "",
	}}
}

// smbProbePorts tries 445 and 139 and returns the open ports as a
// models.PortInfo slice ready for the SMB tester.
func smbProbePorts(ctx context.Context, d *net.Dialer, host string) []models.PortInfo {
	for _, p := range []int{445, 139} {
		if out := tcpProbe(ctx, d, host, p); out != nil {
			return out
		}
	}
	return nil
}

// ldapProbePorts tries 636 (LDAPS) and 389 (LDAP).
func ldapProbePorts(ctx context.Context, d *net.Dialer, host string) []models.PortInfo {
	for _, p := range []int{636, 389} {
		if out := tcpProbe(ctx, d, host, p); out != nil {
			return out
		}
	}
	return nil
}

// snmpProbePorts tries UDP/161. UDP "open" detection is best-effort.
func snmpProbePorts(ctx context.Context, d *net.Dialer, host string) []models.PortInfo {
	addr := net.JoinHostPort(host, "161")
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 128)
	// Send a tiny GetBulk for sysDescr to elicit any response.
	if _, err := conn.Write([]byte{0x30, 0x26, 0x02, 0x01, 0x01, 0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c', 0xa5,
		0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x05, 0x30, 0x0e, 0x30, 0x0c, 0x06,
		0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00}); err != nil {
		conn.Close()
		return nil
	}
	n, _ := conn.Read(buf)
	conn.Close()
	state := "open|filtered"
	if n > 0 {
		state = "open"
	}
	return []models.PortInfo{{Port: 161, Protocol: "udp", State: state, Service: "snmp"}}
}

// ftpProbePorts tries TCP/21.
func ftpProbePorts(ctx context.Context, d *net.Dialer, host string) []models.PortInfo {
	return tcpProbe(ctx, d, host, 21)
}

// _ suppresses the unused fmt import warning when the file is trimmed down.
var _ = fmt.Sprint
