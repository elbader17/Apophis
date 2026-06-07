package web

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

type WebScanner struct {
	client *http.Client
}

func NewWebScanner(timeout time.Duration) *WebScanner {
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &WebScanner{
		client: &http.Client{
			Timeout:   timeout,
			Transport: tr,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (w *WebScanner) Fetch(ctx context.Context, rawURL string) (*models.HTTPInfo, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" {
		u.Scheme = "http"
	}

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Apophis/0.1 (Security Audit)")
	req.Header.Set("Accept", "*/*")

	start := time.Now()
	resp, err := w.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	elapsed := time.Since(start)

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536))

	info := &models.HTTPInfo{
		URL:            u.String(),
		StatusCode:     resp.StatusCode,
		Title:          extractTitle(string(body)),
		Server:         resp.Header.Get("Server"),
		PoweredBy:      resp.Header.Get("X-Powered-By"),
		Headers:        flattenHeaders(resp.Header),
		ResponseTimeMs: elapsed.Milliseconds(),
	}

	if u.Scheme == "https" {
		info.TLS = extractTLSInfo(resp.TLS)
	}
	return info, nil
}

func (w *WebScanner) Client() *http.Client { return w.client }

func (w *WebScanner) Discover(ctx context.Context, host string, ports []int) []models.HTTPInfo {
	candidates := []string{}
	schemes := []string{"http", "https"}
	probePorts := []int{80, 443, 8080, 8443, 8000, 8888}
	for _, p := range ports {
		if p == 80 || p == 443 || p == 8080 || p == 8443 || p == 8000 || p == 8888 {
			probePorts = append(probePorts, p)
		}
	}

	seen := map[string]bool{}
	results := []models.HTTPInfo{}
	for _, p := range probePorts {
		for _, s := range schemes {
			u := fmt.Sprintf("%s://%s:%d/", s, host, p)
			if seen[u] {
				continue
			}
			seen[u] = true
			candidates = append(candidates, u)
		}
	}

	for _, u := range candidates {
		select {
		case <-ctx.Done():
			return results
		default:
		}
		info, err := w.Fetch(ctx, u)
		if err == nil && info.StatusCode > 0 {
			results = append(results, *info)
		}
	}
	return results
}

func (w *WebScanner) CheckDirectoryTraversal(ctx context.Context, baseURL string) []string {
	vectors := []string{
		"../../../../etc/passwd",
		"..\\..\\..\\..\\windows\\win.ini",
		"....//....//....//....//etc/passwd",
		"..%2f..%2f..%2f..%2fetc%2fpasswd",
		"%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
	}
	signatures := []string{
		"root:x:0:0",
		"[fonts]",
		"[extensions]",
		"daemon:x:",
	}

	evidence := []string{}
	for _, v := range vectors {
		u := strings.TrimRight(baseURL, "/") + "/" + v
		req, _ := http.NewRequestWithContext(ctx, "GET", u, nil)
		resp, err := w.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		text := strings.ToLower(string(body))
		for _, sig := range signatures {
			if strings.Contains(text, strings.ToLower(sig)) {
				evidence = append(evidence, fmt.Sprintf("LFI/Dir-Trav via '%s' returns signature '%s'", v, sig))
			}
		}
	}
	return evidence
}

func (w *WebScanner) CheckSQLInjection(ctx context.Context, baseURL string) []string {
	vectors := []string{
		"'",
		"' OR '1'='1",
		"' OR 1=1--",
		"\" OR \"\"=\"",
		"1' ORDER BY 1--",
		"1 UNION SELECT NULL--",
	}
	signatures := []string{
		"sql syntax",
		"mysql_fetch",
		"mysqli_",
		"unclosed quotation mark",
		"odbc sql server driver",
		"ora-00933",
		"pg_query()",
		"supplied argument is not a valid",
		"warning: mysql",
		"you have an error in your sql syntax",
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	q := u.Query()
	original := q.Get("q")
	param := "q"
	if original == "" {
		q.Set(param, "test")
		original = "test"
	}

	evidence := []string{}
	for _, v := range vectors {
		q.Set(param, original+v)
		u.RawQuery = q.Encode()
		req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		resp, err := w.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 16384))
		resp.Body.Close()
		text := strings.ToLower(string(body))
		for _, sig := range signatures {
			if strings.Contains(text, sig) {
				evidence = append(evidence, fmt.Sprintf("Possible SQLi via param '%s' vector '%s' (signature: %s)", param, v, sig))
			}
		}
	}
	return evidence
}

func (w *WebScanner) CheckXSS(ctx context.Context, baseURL string) []string {
	vectors := []string{
		"<script>apophis</script>",
		"\"><svg/onload=apophis>",
		"'><img src=x onerror=apophis>",
	}
	evidence := []string{}
	for _, v := range vectors {
		u, err := url.Parse(baseURL)
		if err != nil {
			continue
		}
		q := u.Query()
		q.Set("q", v)
		u.RawQuery = q.Encode()
		req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
		resp, err := w.client.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32768))
		resp.Body.Close()
		if strings.Contains(string(body), v) {
			evidence = append(evidence, fmt.Sprintf("Reflected XSS via vector '%s'", v))
		}
	}
	return evidence
}

func (w *WebScanner) CheckSecurityHeaders(headers map[string]string) []string {
	critical := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Referrer-Policy",
	}
	exposed := []string{
		"Server",
		"X-Powered-By",
	}

	low := []string{}
	for _, h := range critical {
		if _, ok := headers[http.CanonicalHeaderKey(h)]; !ok {
			low = append(low, fmt.Sprintf("Missing security header: %s", h))
		}
	}
	for _, h := range exposed {
		if v, ok := headers[http.CanonicalHeaderKey(h)]; ok && v != "" {
			low = append(low, fmt.Sprintf("Information disclosure header: %s: %s", h, v))
		}
	}
	return low
}

func extractTLSInfo(cs *tls.ConnectionState) *models.TLSInfo {
	if cs == nil {
		return nil
	}
	info := &models.TLSInfo{}
	if len(cs.PeerCertificates) > 0 {
		cert := cs.PeerCertificates[0]
		info.Expires = cert.NotAfter.Format("2006-01-02")
		info.SelfSigned = cs.PeerCertificates[0].Issuer.String() == cs.PeerCertificates[0].Subject.String()
	}
	info.Version = tlsVersionName(cs.Version)
	info.Cipher = tls.CipherSuiteName(cs.CipherSuite)
	if info.Version != "TLS 1.3" && info.Version != "TLS 1.2" {
		info.Issues = append(info.Issues, fmt.Sprintf("Weak/outdated TLS version: %s", info.Version))
	}
	if info.SelfSigned {
		info.Issues = append(info.Issues, "Self-signed certificate")
	}
	return info
}

func tlsVersionName(v uint16) string {
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

func flattenHeaders(h http.Header) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		out[k] = strings.Join(v, ", ")
	}
	return out
}

var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(html string) string {
	m := titleRe.FindStringSubmatch(html)
	if len(m) > 1 {
		return strings.TrimSpace(m[1])
	}
	return ""
}
