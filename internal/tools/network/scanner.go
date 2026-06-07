package network

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

var commonPorts = map[int]string{
	21:    "ftp",
	22:    "ssh",
	23:    "telnet",
	25:    "smtp",
	53:    "dns",
	80:    "http",
	110:   "pop3",
	111:   "rpcbind",
	135:   "msrpc",
	139:   "netbios-ssn",
	143:   "imap",
	161:   "snmp",
	389:   "ldap",
	443:   "https",
	445:   "smb",
	465:   "smtps",
	514:   "syslog",
	587:   "submission",
	631:   "ipp",
	636:   "ldaps",
	993:   "imaps",
	995:   "pop3s",
	1433:  "mssql",
	1521:  "oracle",
	2049:  "nfs",
	3306:  "mysql",
	3389:  "rdp",
	5432:  "postgres",
	5900:  "vnc",
	6379:  "redis",
	8000:  "http-alt",
	8080:  "http-proxy",
	8443:  "https-alt",
	8888:  "http-alt",
	9200:  "elasticsearch",
	11211: "memcached",
	27017: "mongodb",
}

type PortScanner struct {
	timeout time.Duration
}

func NewPortScanner(timeout time.Duration) *PortScanner {
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	return &PortScanner{timeout: timeout}
}

func (p *PortScanner) Scan(ctx context.Context, host string, ports []int) []models.PortInfo {
	if len(ports) == 0 {
		ports = CommonPortsList()
	}

	var (
		mu      sync.Mutex
		results = make([]models.PortInfo, 0)
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 100)
	)

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return results
		default:
		}

		wg.Add(1)
		sem <- struct{}{}
		go func(port int) {
			defer wg.Done()
			defer func() { <-sem }()

			info := p.probe(ctx, host, port)
			if info != nil {
				mu.Lock()
				results = append(results, *info)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return results
}

func (p *PortScanner) probe(ctx context.Context, host string, port int) *models.PortInfo {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := net.Dialer{Timeout: p.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()

	info := &models.PortInfo{
		Port:     port,
		Protocol: "tcp",
		State:    "open",
		Service:  guessService(port),
	}
	info.Banner = grabBanner(ctx, conn, port)
	info.Version = parseVersion(info.Banner, info.Service)
	return info
}

func grabBanner(ctx context.Context, conn net.Conn, port int) string {
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	defer conn.SetReadDeadline(time.Time{})

	payloads := map[string][]byte{
		"ssh":     []byte("SSH-2.0-OpenSSH_Probe\r\n"),
		"http":    []byte("HEAD / HTTP/1.0\r\n\r\n"),
		"smtp":    []byte("EHLO probe\r\n"),
		"ftp":     []byte("USER anonymous\r\n"),
		"pop3":    []byte("USER probe\r\n"),
		"imap":    []byte(". CAPABILITY\r\n"),
	}
	if payload, ok := payloads[guessService(port)]; ok {
		conn.Write(payload)
	}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	raw := string(buf[:n])
	if idx := strings.IndexAny(raw, "\r\n"); idx > 0 {
		raw = raw[:idx]
	}
	cleaned := make([]rune, 0, len(raw))
	for _, r := range raw {
		if r >= 32 && r < 127 || r == '\t' {
			cleaned = append(cleaned, r)
		}
	}
	if len(cleaned) > 200 {
		cleaned = cleaned[:200]
	}
	return strings.TrimSpace(string(cleaned))
}

func guessService(port int) string {
	if s, ok := commonPorts[port]; ok {
		return s
	}
	return "unknown"
}

func parseVersion(banner, service string) string {
	banner = strings.ToLower(banner)
	switch service {
	case "ssh":
		if strings.HasPrefix(banner, "ssh-") {
			parts := strings.Split(banner, "-")
			if len(parts) >= 3 {
				return strings.Split(parts[2], " ")[0]
			}
		}
	case "http", "https":
		if strings.Contains(banner, "server:") {
			for _, line := range strings.Split(banner, "\n") {
				if strings.HasPrefix(strings.ToLower(line), "server:") {
					return strings.TrimSpace(line[7:])
				}
			}
		}
	}
	return ""
}

func CommonPortsList() []int {
	ports := make([]int, 0, len(commonPorts))
	for p := range commonPorts {
		ports = append(ports, p)
	}
	return ports
}

func (p *PortScanner) Describe() string {
	return fmt.Sprintf("PortScanner(timeout=%s)", p.timeout)
}
