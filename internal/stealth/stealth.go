// Package stealth implements the evasion primitives used by the port
// scanner and the web probes:
//
//   - Pacer: a rate-limiter with adaptive backoff and per-probe jitter.
//   - DecoyRouter: a noise generator that issues benign probes against a
//     list of decoy IPs/hosts to dilute the audit trail.
//   - WAFDetector: identifies a WAF / CDN in front of a target by sending
//     an obvious payload and inspecting the response for vendor-specific
//     fingerprints.
//   - EvasionProfile: a per-strategy bundle of knobs the scanners apply.
//
// The package does not implement raw-socket source spoofing; it focuses on
// behaviour the user-space scanner can actually pull off without root.
package stealth

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/apophis-eng/apophis/internal/logger"
	"github.com/apophis-eng/apophis/internal/models"
)

// Pacer enforces a per-second probe budget with jitter.
type Pacer struct {
	mu          sync.Mutex
	interval    time.Duration
	jitter      time.Duration
	maxInflight int
	sem         chan struct{}
	last        time.Time
	// Adaptive state — counts timeouts/refusals and slows down when they
	// exceed the threshold.
	timeouts   atomic.Int64
	refusals   atomic.Int64
	success    atomic.Int64
	adaptive   bool
	slowFactor float64
}

// NewPacer returns a pacer that targets rate probes/sec with up to jitter
// extra ms of random delay per probe. maxInflight bounds concurrency.
func NewPacer(ratePerSec int, jitterMs int, maxInflight int) *Pacer {
	if ratePerSec <= 0 {
		ratePerSec = 50
	}
	if maxInflight <= 0 {
		maxInflight = 16
	}
	interval := time.Second / time.Duration(ratePerSec)
	return &Pacer{
		interval:    interval,
		jitter:      time.Duration(jitterMs) * time.Millisecond,
		maxInflight: maxInflight,
		sem:         make(chan struct{}, maxInflight),
		adaptive:    true,
		slowFactor:  1.0,
	}
}

// Acquire blocks until the pacer allows one more probe. Callers must call
// Release when the probe is done. ctx is honoured.
func (p *Pacer) Acquire(ctx context.Context) error {
	select {
	case p.sem <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	p.mu.Lock()
	wait := p.interval
	if p.slowFactor != 1.0 {
		wait = time.Duration(float64(wait) * p.slowFactor)
	}
	if p.jitter > 0 {
		wait += time.Duration(rand.Int63n(int64(p.jitter)))
	}
	last := p.last
	p.last = time.Now()
	p.mu.Unlock()
	if !last.IsZero() {
		d := time.Until(last.Add(wait))
		if d > 0 {
			t := time.NewTimer(d)
			defer t.Stop()
			select {
			case <-t.C:
			case <-ctx.Done():
				<-p.sem
				return ctx.Err()
			}
		}
	}
	return nil
}

// Release returns one in-flight slot.
func (p *Pacer) Release() { <-p.sem }

// ReportTimeout signals a slow probe (no response) and updates the adaptive
// backoff state.
func (p *Pacer) ReportTimeout() {
	if !p.adaptive {
		return
	}
	t := p.timeouts.Add(1)
	total := t + p.success.Load() + p.refusals.Load()
	if total < 20 {
		return
	}
	ratio := float64(t) / float64(total)
	if ratio > 0.2 && p.slowFactor < 4.0 {
		p.slowFactor *= 1.25
		logger.Info("pacer", fmt.Sprintf("adaptive slowdown → x%.2f (timeout ratio %.0f%%)", p.slowFactor, ratio*100))
	}
}

// ReportRefusal signals an explicit RST/refused connection.
func (p *Pacer) ReportRefusal() {
	if !p.adaptive {
		return
	}
	r := p.refusals.Add(1)
	total := r + p.success.Load() + p.timeouts.Load()
	if total < 20 {
		return
	}
	ratio := float64(r) / float64(total)
	if ratio > 0.3 && p.slowFactor < 6.0 {
		p.slowFactor *= 1.5
		logger.Warn("pacer", fmt.Sprintf("refusal surge — backing off to x%.2f", p.slowFactor))
	}
}

// ReportSuccess notes a successful probe.
func (p *Pacer) ReportSuccess() { p.success.Add(1) }

// --- Decoy routing ---------------------------------------------------------

// DecoyRouter issues benign probes against a list of decoy IPs/hosts in
// parallel with the real audit. The intent is to dilute the audit trail in
// the target's log files so the real scan blends in. Without raw sockets we
// cannot truly spoof source IPs — the best we can do is generate HTTP noise
// to decoys so the attacker's source appears as one of many.
type DecoyRouter struct {
	Decoys []string
	Client *http.Client
}

// IsDecoy returns true if target matches one of the configured decoys. Used
// by the orchestrator to suppress audit-phase findings on decoy targets.
func (d *DecoyRouter) IsDecoy(target string) bool {
	for _, x := range d.Decoys {
		if strings.EqualFold(x, target) {
			return true
		}
	}
	return false
}

// Noise fires one benign GET per decoy in parallel and returns when all
// have completed or the context is cancelled. Errors are intentionally
// swallowed: this is best-effort camouflage.
func (d *DecoyRouter) Noise(ctx context.Context) {
	if d.Client == nil {
		d.Client = &http.Client{Timeout: 4 * time.Second}
	}
	var wg sync.WaitGroup
	for _, host := range d.Decoys {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			for _, scheme := range []string{"http", "https"} {
				url := fmt.Sprintf("%s://%s/", scheme, h)
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; mass-scanner/1.0)")
				resp, err := d.Client.Do(req)
				if err == nil {
					resp.Body.Close()
				}
			}
		}(host)
	}
	wg.Wait()
}

// --- WAF detection ---------------------------------------------------------

// wafSigs maps lowercased vendor identifiers to the response markers that
// announce them. The detector checks headers, cookies and the body of the
// baseline probe (a typical harmless request) and the malicious probe (a
// classic XSS / SQLi payload expected to be blocked by most WAFs).
var wafSigs = []struct {
	Vendor   string
	Headers  []string // header name substrings (case-insensitive)
	Cookies  []string // cookie name substrings (case-insensitive)
	BodySubs []string // body substrings (case-insensitive)
	Blocked  []string // body substrings indicating "blocked" (used to mark Blocked=true)
}{
	{Vendor: "cloudflare", Headers: []string{"cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"}, Cookies: []string{"__cfduid", "cf_clearance"}},
	{Vendor: "akamai", Headers: []string{"akamai", "x-akamai", "x-akamai-transformed"}},
	{Vendor: "aws", Headers: []string{"x-amzn-waf", "x-amz-cf-id", "x-amz-id-2"}},
	{Vendor: "imperva", Headers: []string{"x-cdn", "x-iinfo", "incapsula"}},
	{Vendor: "f5", Headers: []string{"x-wa-info", "bigip", "f5-"}, BodySubs: []string{"the requested url was rejected"}},
	{Vendor: "sucuri", Headers: []string{"x-sucuri", "x-sucuri-id"}, BodySubs: []string{"sucuri website firewall", "access denied - sucuri"}},
	{Vendor: "modsecurity", Headers: []string{"mod_security", "modsecurity"}, BodySubs: []string{"mod_security", "modsecurity", "owasp crs", "this request was blocked"}},
	{Vendor: "barracuda", Headers: []string{"barra", "barracuda"}, BodySubs: []string{"barracuda"}},
	{Vendor: "wordfence", BodySubs: []string{"wordfence", "this response was generated by wordfence"}},
	{Vendor: "fastly", Headers: []string{"fastly", "x-served-by", "x-cache"}},
	{Vendor: "cloudfront", Headers: []string{"x-amz-cf-id", "cloudfront"}},
}

// WAFDetector probes a target and returns a WAFInfo if a vendor matches.
type WAFDetector struct {
	Client  *http.Client
	Payload string
}

// NewWAFDetector returns a detector with a sane default payload.
func NewWAFDetector(timeout time.Duration) *WAFDetector {
	return &WAFDetector{
		Client:  &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }},
		Payload: "?apophis=<script>alert(1)</script>",
	}
}

// Detect issues a baseline GET and a malicious GET. It compares the responses
// for header/cookie/body fingerprints and returns the first matching vendor.
func (w *WAFDetector) Detect(ctx context.Context, base string) *models.WAFInfo {
	if base == "" {
		return nil
	}
	baseline := w.probe(ctx, base)
	if baseline == nil {
		return nil
	}
	mal := w.probe(ctx, base+w.Payload)
	if mal == nil {
		// We still have the baseline; some WAFs are visible there.
		mal = baseline
	}
	for _, sig := range wafSigs {
		evidence := []string{}
		for _, h := range sig.Headers {
			for k := range baseline.Headers {
				if strings.Contains(strings.ToLower(k), h) {
					evidence = append(evidence, "header:"+k)
				}
			}
			if mal != baseline {
				for k := range mal.Headers {
					if strings.Contains(strings.ToLower(k), h) {
						evidence = append(evidence, "header(after-payload):"+k)
					}
				}
			}
		}
		for _, c := range sig.Cookies {
			for _, ck := range baseline.Cookies {
				if strings.Contains(strings.ToLower(ck), c) {
					evidence = append(evidence, "cookie:"+ck)
				}
			}
		}
		for _, sub := range sig.BodySubs {
			if strings.Contains(strings.ToLower(baseline.Body), sub) {
				evidence = append(evidence, "body:"+sub)
			}
		}
		if len(evidence) == 0 {
			continue
		}
		blocked := false
		for _, sub := range sig.Blocked {
			if strings.Contains(strings.ToLower(mal.Body), sub) {
				blocked = true
			}
		}
		if !blocked && mal.Status == 0 {
			blocked = false
		}
		if mal.Status == 403 || mal.Status == 406 || mal.Status == 429 || mal.Status == 503 {
			blocked = true
		}
		return &models.WAFInfo{Vendor: sig.Vendor, Evidence: evidence, Blocked: blocked}
	}
	return nil
}

type wafResp struct {
	Headers http.Header
	Cookies []string
	Body    string
	Status  int
}

func (w *WAFDetector) probe(ctx context.Context, url string) *wafResp {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; apophis/1.0)")
	resp, err := w.Client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
			if len(body) > 1<<16 {
				break
			}
		}
		if err != nil {
			break
		}
	}
	cookies := []string{}
	for _, c := range resp.Cookies() {
		cookies = append(cookies, c.Name)
	}
	return &wafResp{Headers: resp.Header, Cookies: cookies, Body: string(body), Status: resp.StatusCode}
}

// --- Evasion profile -------------------------------------------------------

// EvasionProfile bundles the knobs the scanners apply to each request.
type EvasionProfile struct {
	Level        string   // "off"|"low"|"medium"|"high"
	UserAgents   []string // pool of UAs to rotate
	RandomPaths  bool     // add a random query string to plain GETs
	HeaderOrder  []string // if non-empty, send headers in this order
	AcceptLang   string
	Encoding     string // "gzip"|"deflate"|""
	ExtraHeaders []KV
}

type KV struct{ Key, Value string }

// NewEvasionProfile returns a sensible default per level.
func NewEvasionProfile(level string) EvasionProfile {
	switch strings.ToLower(level) {
	case "high":
		return EvasionProfile{
			Level:       "high",
			RandomPaths: true,
			UserAgents:  highUA,
			AcceptLang:  randomAcceptLang(),
			Encoding:    "gzip",
		}
	case "medium":
		return EvasionProfile{
			Level:       "medium",
			RandomPaths: false,
			UserAgents:  mediumUA,
			AcceptLang:  "en-US,en;q=0.9",
		}
	case "low":
		return EvasionProfile{
			Level:      "low",
			UserAgents: []string{"Mozilla/5.0"},
		}
	}
	return EvasionProfile{Level: "off"}
}

// Apply returns the headers / URL modifications to use for the next request.
func (e EvasionProfile) Apply(req *http.Request, baseURL string) {
	if req == nil {
		return
	}
	if len(e.UserAgents) > 0 {
		req.Header.Set("User-Agent", e.UserAgents[rand.Intn(len(e.UserAgents))])
	}
	if e.AcceptLang != "" {
		req.Header.Set("Accept-Language", e.AcceptLang)
	}
	if e.Encoding != "" {
		req.Header.Set("Accept-Encoding", e.Encoding)
	}
	for _, kv := range e.ExtraHeaders {
		req.Header.Set(kv.Key, kv.Value)
	}
}

func randomAcceptLang() string {
	languages := []string{"en-US,en;q=0.9", "fr-FR,fr;q=0.9", "de-DE,de;q=0.9", "es-ES,es;q=0.9", "ja,en;q=0.8"}
	return languages[rand.Intn(len(languages))]
}

var (
	highUA = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
	}
	mediumUA = []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
	}
)

// ApplyToOptions returns a func suitable for wrapping an http.Client so the
// scanner can use the evasion profile without re-writing call sites.
func (e EvasionProfile) ApplyToOptions() func(*http.Request) {
	return func(req *http.Request) {
		e.Apply(req, req.URL.String())
	}
}
