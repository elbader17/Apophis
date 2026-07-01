// Package ftp performs an anonymous-bind and weak-credentials probe against
// FTP services. We do not implement the full RFC 959 client — only the
// banner, USER, PASS, SYST, HELP and PWD commands needed to fingerprint the
// server and detect anonymous access.
package ftp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

const portFTP = 21

// Tester probes FTP.
type Tester struct {
	Timeout time.Duration
	// AllowAnonymous, when true, tries USER anonymous / PASS anonymous@
	// (and several variants).
	AllowAnonymous bool
	// TryCreds is a list of additional (user, pass) pairs to test. The
	// default list includes common vendor defaults.
	TryCreds [][2]string
}

func New(t time.Duration) *Tester {
	if t == 0 {
		t = 5 * time.Second
	}
	return &Tester{
		Timeout:        t,
		AllowAnonymous: true,
		TryCreds: [][2]string{
			{"ftp", "ftp"},
			{"ftp", "ftp@"},
			{"admin", "admin"},
			{"admin", "password"},
			{"root", "root"},
			{"root", "password"},
			{"test", "test"},
			{"user", "user"},
			{"anonymous", "anonymous"},
			{"anonymous", ""},
			{"anonymous", "guest"},
			{"anonymous", "ftp@"},
		},
	}
}

// Info is the gathered state.
type Info struct {
	Port          int
	Banner        string
	SYST          string
	HELP          string
	WorkingDir    string
	AnonymousOK   bool
	AcceptedCreds [][2]string
	TLSAdvertised bool
}

// Audit probes the FTP service.
func (t *Tester) Audit(ctx context.Context, host string, ports []models.PortInfo) ([]models.Finding, *Info) {
	targetPort := portFTP
	if !portOpen(ports, targetPort) {
		return nil, nil
	}
	info := &Info{Port: targetPort}

	d := net.Dialer{Timeout: t.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", targetPort)))
	if err != nil {
		return nil, info
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(t.Timeout))

	br := bufio.NewReader(conn)
	// Read banner.
	banner, err := readReply(br)
	if err != nil || !strings.HasPrefix(banner, "220") {
		return nil, info
	}
	info.Banner = banner

	// SYST.
	fmt.Fprintf(conn, "SYST\r\n")
	if line, err := readReply(br); err == nil && strings.HasPrefix(line, "215") {
		info.SYST = strings.TrimSpace(line[4:])
	}
	// HELP (one line at a time).
	fmt.Fprintf(conn, "HELP\r\n")
	if line, err := readReply(br); err == nil {
		if strings.Contains(line, "AUTH TLS") || strings.Contains(line, "STARTTLS") {
			info.TLSAdvertised = true
		}
		info.HELP = strings.TrimSpace(line)
	}

	// Anonymous probe.
	if t.AllowAnonymous {
		if err := tryLogin(br, conn, "anonymous", "anonymous@"); err == nil {
			info.AnonymousOK = true
			info.AcceptedCreds = append(info.AcceptedCreds, [2]string{"anonymous", "anonymous@"})
			// PWD for completeness.
			fmt.Fprintf(conn, "PWD\r\n")
			if line, err := readReply(br); err == nil {
				info.WorkingDir = strings.TrimSpace(line)
			}
			fmt.Fprintf(conn, "QUIT\r\n")
			_, _ = readReply(br)
		}
	}
	// Default-cred probe (uses a fresh connection per attempt to avoid
	// being kicked on bad logins — many servers disconnect after N failures).
	for _, c := range t.TryCreds {
		if c[0] == "anonymous" {
			continue
		}
		if t.tryCred(ctx, host, targetPort, c[0], c[1]) {
			info.AcceptedCreds = append(info.AcceptedCreds, c)
		}
	}

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

func tryLogin(br *bufio.Reader, conn net.Conn, user, pass string) error {
	fmt.Fprintf(conn, "USER %s\r\n", user)
	line, err := readReply(br)
	if err != nil {
		return err
	}
	if strings.HasPrefix(line, "230") {
		return nil // Logged in without needing PASS.
	}
	if !strings.HasPrefix(line, "331") {
		return fmt.Errorf("unexpected USER reply: %q", line)
	}
	fmt.Fprintf(conn, "PASS %s\r\n", pass)
	line2, err := readReply(br)
	if err != nil {
		return err
	}
	if strings.HasPrefix(line2, "230") {
		return nil
	}
	return fmt.Errorf("login failed: %q", line2)
}

// tryCred opens a fresh connection for a single credential attempt.
func (t *Tester) tryCred(ctx context.Context, host string, port int, user, pass string) bool {
	d := net.Dialer{Timeout: t.Timeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, fmt.Sprintf("%d", port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(t.Timeout))
	br := bufio.NewReader(conn)
	if banner, err := readReply(br); err != nil || !strings.HasPrefix(banner, "220") {
		return false
	}
	return tryLogin(br, conn, user, pass) == nil
}

// readReply reads a single FTP reply (potentially multi-line). Returns the
// trimmed reply text (without the leading "NNN-" / "NNN " marker).
func readReply(br *bufio.Reader) (string, error) {
	var (
		lines []string
		code  string
	)
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			if len(lines) == 0 {
				return "", err
			}
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			break
		}
		c := line[:3]
		if code == "" {
			code = c
		}
		lines = append(lines, line)
		if c != code || len(line) < 4 {
			break
		}
		if line[3] == ' ' {
			break
		}
	}
	return strings.TrimSpace(strings.Join(lines, " ")), nil
}

func (t *Tester) toFindings(host string, info *Info) []models.Finding {
	f := []models.Finding{}
	if info.AnonymousOK {
		f = append(f, models.Finding{
			Title:       fmt.Sprintf("FTP anonymous login allowed on %s:%d", host, info.Port),
			Severity:    models.SeverityHigh,
			Category:    "FTP",
			Target:      host,
			Port:        info.Port,
			Evidence:    "USER anonymous + PASS anonymous@ succeeded; " + info.WorkingDir,
			Description: "The FTP service permits anonymous read/write access. If write access is granted in any directory, the server becomes a malware drop / exfiltration point. Even read-only anonymous access often leaks sensitive files (config backups, customer lists, source code).",
			Exploit:     "ftp <target> (anonymous / anonymous@); wget -m ftp://anonymous:anonymous@@<target>/",
			Remediation: "Disable anonymous FTP. Use SFTP/FTPS or move to HTTPS-based file transfer. If anonymous access is required, isolate it to a chroot and ensure no write permissions.",
			References:  []string{"https://owasp.org/www-community/vulnerabilities/FTP_Bounce_attack"},
			Tags:        []string{"ftp", "anonymous"},
		})
	}
	if len(info.AcceptedCreds) > 0 && !info.AnonymousOK {
		pairs := []string{}
		for _, c := range info.AcceptedCreds {
			pairs = append(pairs, fmt.Sprintf("%s:%s", c[0], c[1]))
		}
		f = append(f, models.Finding{
			Title:       fmt.Sprintf("FTP weak credentials on %s:%d (%s)", host, info.Port, strings.Join(pairs, ", ")),
			Severity:    models.SeverityCritical,
			Category:    "FTP",
			Target:      host,
			Port:        info.Port,
			Evidence:    "login succeeded for at least one default credential",
			Description: "The FTP service accepted one or more default / weak credentials. Plain-text FTP transmits the password in cleartext, so any network observer can read it as well.",
			Exploit:     "hydra -L users.txt -P passwords.txt ftp://<target>; medusa -h <target> -u admin -p password -M ftp",
			Remediation: "Force strong passwords, disable FTP in favour of SFTP/FTPS, and enforce fail2ban or IP allow-listing.",
			Tags:        []string{"ftp", "default-creds", "cleartext"},
		})
	}
	if info.TLSAdvertised {
		f = append(f, models.Finding{
			Title:       fmt.Sprintf("FTP STARTTLS advertised on %s:%d (insufficient)", host, info.Port),
			Severity:    models.SeverityLow,
			Category:    "FTP",
			Target:      host,
			Port:        info.Port,
			Evidence:    "Server advertises AUTH TLS / STARTTLS — confirm it's enforced",
			Description: "FTP STARTTLS can be downgraded by an active MITM. Confirm the server rejects plain FTP logins when AUTH TLS is enabled.",
			Exploit:     "Use ftps-ssl-strip / generic MITM to bypass STARTTLS where the server allows both.",
			Remediation: "Reject plain FTP logins and require AUTH TLS before USER/PASS.",
			Tags:        []string{"ftp", "starttls"},
		})
	}
	if info.SYST != "" {
		f = append(f, models.Finding{
			Title:       fmt.Sprintf("FTP SYST disclosure on %s:%d", host, info.Port),
			Severity:    models.SeverityInfo,
			Category:    "FTP",
			Target:      host,
			Port:        info.Port,
			Evidence:    "SYST=" + info.SYST,
			Description: "The SYST command leaks the server software and version. Use to focus exploit selection.",
			Exploit:     "Run apophis_check_cve service=ftp version=<banner>.",
			Remediation: "Use a hardened FTP server that masks SYST (e.g. vsftpd with `ftpd_banner=` masking).",
			Tags:        []string{"ftp", "disclosure"},
		})
	}
	return f
}
