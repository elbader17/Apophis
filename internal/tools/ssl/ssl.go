package ssl

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

type SSLTester struct {
	timeout time.Duration
}

func NewSSLTester(timeout time.Duration) *SSLTester {
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	return &SSLTester{timeout: timeout}
}

func (s *SSLTester) Inspect(ctx context.Context, host string, port int) *models.TLSInfo {
	dialer := &net.Dialer{Timeout: s.timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, strconv.Itoa(port)), &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	info := &models.TLSInfo{
		Version: tlsVersion(state.Version),
		Cipher:  tls.CipherSuiteName(state.CipherSuite),
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		info.Expires = cert.NotAfter.Format("2006-01-02")
		info.SelfSigned = cert.Issuer.String() == cert.Subject.String()
	}

	if state.Version < tls.VersionTLS12 {
		info.Issues = append(info.Issues, fmt.Sprintf("Deprecated TLS version: %s", info.Version))
	}
	if info.SelfSigned {
		info.Issues = append(info.Issues, "Self-signed certificate")
	}
	if time.Until(state.PeerCertificates[0].NotAfter) < 30*24*time.Hour {
		info.Issues = append(info.Issues, "Certificate expires within 30 days")
	}
	weakCiphers := []uint16{
		tls.TLS_RSA_WITH_RC4_128_SHA,
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
		tls.TLS_RSA_WITH_AES_128_CBC_SHA,
	}
	for _, c := range weakCiphers {
		if state.CipherSuite == c {
			info.Issues = append(info.Issues, fmt.Sprintf("Weak cipher in use: %s", info.Cipher))
			break
		}
	}
	return info
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	}
	return fmt.Sprintf("unknown(0x%04x)", v)
}
