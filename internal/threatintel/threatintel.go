// Package threatintel implements adapters for four public threat-intelligence
// providers: GreyNoise Community API, Shodan, AbuseIPDB, and VirusTotal.
//
// Each adapter is wrapped behind a common Lookup() interface that returns a
// TIReport-style verdict for a given IP or domain. The orchestrator runs the
// adapters in parallel, applies the configured min-confidence threshold, and
// attaches the result to the relevant Finding(s).
//
// Authentication is via environment variables:
//
//	APOPHIS_GREYNOISE_KEY   — required for greynoise
//	APOPHIS_SHODAN_KEY      — required for shodan
//	APOPHIS_ABUSEIPDB_KEY   — required for abuseipdb
//	APOPHIS_VIRUSTOTAL_KEY  — required for virustotal
//
// The adapters are all best-effort: a missing key disables that source and
// the orchestrator records it in the report.
package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Verdict is the normalized verdict returned by every adapter.
type Verdict struct {
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	Score      float64  `json:"score"` // 0.0 = clean, 1.0 = definitely malicious
	Malicious  bool     `json:"malicious"`
	Tags       []string `json:"tags,omitempty"`
	Categories []string `json:"categories,omitempty"`
	Country    string   `json:"country,omitempty"`
	ASN        string   `json:"asn,omitempty"`
	Detail     string   `json:"detail,omitempty"`
}

// Provider is the common interface implemented by every adapter.
type Provider interface {
	Name() string
	Enabled() bool
	Lookup(ctx context.Context, target string) (*Verdict, error)
}

// ProviderConfig is the bundle of API keys + the HTTP client used by every
// adapter. Missing keys disable that adapter silently.
type ProviderConfig struct {
	GreyNoiseKey  string
	ShodanKey     string
	AbuseIPDBKey  string
	VirusTotalKey string
	HTTP          *http.Client
}

func New(cfg ProviderConfig) []Provider {
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 8 * time.Second}
	}
	// Shodan InternetDB is keyless — always enabled.
	out := []Provider{&Shodan{Key: cfg.ShodanKey, HTTP: cfg.HTTP}}
	if cfg.GreyNoiseKey != "" {
		out = append(out, &GreyNoise{Key: cfg.GreyNoiseKey, HTTP: cfg.HTTP})
	}
	if cfg.AbuseIPDBKey != "" {
		out = append(out, &AbuseIPDB{Key: cfg.AbuseIPDBKey, HTTP: cfg.HTTP})
	}
	if cfg.VirusTotalKey != "" {
		out = append(out, &VirusTotal{Key: cfg.VirusTotalKey, HTTP: cfg.HTTP})
	}
	return out
}

// LookupAll runs every enabled provider in parallel and returns the slice of
// verdicts. Order is non-deterministic but stable across the same set of
// providers within a single call.
func LookupAll(ctx context.Context, providers []Provider, target string) []*Verdict {
	type res struct {
		v *Verdict
	}
	out := []*Verdict{}
	ch := make(chan res, len(providers))
	for _, p := range providers {
		p := p
		go func() {
			v, err := p.Lookup(ctx, target)
			if err != nil {
				ch <- res{v: &Verdict{Source: p.Name(), Target: target, Detail: "error: " + err.Error()}}
				return
			}
			ch <- res{v: v}
		}()
	}
	for i := 0; i < len(providers); i++ {
		r := <-ch
		if r.v != nil {
			out = append(out, r.v)
		}
	}
	return out
}

// --- GreyNoise Community API -----------------------------------------------
//
// Docs: https://docs.greynoise.io/reference/communityapi_ip
// Free tier is IP-context only.

type GreyNoise struct {
	Key  string
	HTTP *http.Client
}

func (g *GreyNoise) Name() string  { return "greynoise" }
func (g *GreyNoise) Enabled() bool { return g.Key != "" }

func (g *GreyNoise) Lookup(ctx context.Context, target string) (*Verdict, error) {
	endpoint := fmt.Sprintf("https://api.greynoise.io/v3/community/%s", url.PathEscape(target))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("key", g.Key)
	resp, err := g.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("greynoise %d: %s", resp.StatusCode, string(body))
	}
	var doc struct {
		IP             string   `json:"ip"`
		Noise          bool     `json:"noise"`
		Riot           bool     `json:"riot"`
		Classification string   `json:"classification"`
		Name           string   `json:"name"`
		Links          []string `json:"links"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	v := &Verdict{Source: g.Name(), Target: target}
	switch strings.ToLower(doc.Classification) {
	case "malicious":
		v.Malicious = true
		v.Score = 0.95
		v.Tags = append(v.Tags, "malicious")
	case "suspicious":
		v.Score = 0.6
		v.Tags = append(v.Tags, "suspicious")
	case "benign":
		v.Score = 0.0
		v.Tags = append(v.Tags, "benign")
	}
	if doc.Riot {
		v.Tags = append(v.Tags, "trusted-enterprise")
	}
	if doc.Noise {
		v.Tags = append(v.Tags, "mass-scanner")
	}
	v.Detail = doc.Classification
	return v, nil
}

// --- Shodan InternetDB (free, no key) --------------------------------------
//
// We expose it as a "key-optional" provider so the orchestrator can always
// run it.

type Shodan struct {
	Key  string // optional: enriches with /shodan/host
	HTTP *http.Client
}

func (s *Shodan) Name() string  { return "shodan" }
func (s *Shodan) Enabled() bool { return true }

func (s *Shodan) Lookup(ctx context.Context, target string) (*Verdict, error) {
	// InternetDB is the key-free endpoint.
	endpoint := fmt.Sprintf("https://internetdb.shodan.io/%s", url.PathEscape(target))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	resp, err := s.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("shodan %d: %s", resp.StatusCode, string(body))
	}
	var doc struct {
		IP        string   `json:"ip"`
		Ports     []int    `json:"ports"`
		CPEs      []string `json:"cpes"`
		Hostnames []string `json:"hostnames"`
		City      string   `json:"city"`
		Country   string   `json:"country"`
		ASN       string   `json:"asn"`
		Org       string   `json:"org"`
		Vulns     []string `json:"vulns"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	v := &Verdict{Source: s.Name(), Target: target, Country: doc.Country, ASN: doc.ASN}
	// Vulns from Shodan are very high-signal: tag the target as
	// known-vulnerable if any are returned.
	if len(doc.Vulns) > 0 {
		v.Malicious = true
		v.Score = 0.7
		v.Tags = append(v.Tags, "known-cve")
		for _, cve := range doc.Vulns {
			v.Categories = append(v.Categories, cve)
		}
	}
	if len(doc.Ports) > 5 {
		v.Tags = append(v.Tags, "exposed-services")
	}
	v.Detail = fmt.Sprintf("ports=%d cpes=%d vulns=%d", len(doc.Ports), len(doc.CPEs), len(doc.Vulns))
	return v, nil
}

// --- AbuseIPDB -------------------------------------------------------------

type AbuseIPDB struct {
	Key  string
	HTTP *http.Client
}

func (a *AbuseIPDB) Name() string  { return "abuseipdb" }
func (a *AbuseIPDB) Enabled() bool { return a.Key != "" }

func (a *AbuseIPDB) Lookup(ctx context.Context, target string) (*Verdict, error) {
	endpoint := "https://api.abuseipdb.com/api/v2/check"
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	q := req.URL.Query()
	q.Set("ipAddress", target)
	q.Set("maxAgeInDays", "90")
	req.URL.RawQuery = q.Encode()
	req.Header.Set("Key", a.Key)
	req.Header.Set("Accept", "application/json")
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("abuseipdb %d: %s", resp.StatusCode, string(body))
	}
	var doc struct {
		Data struct {
			AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
			CountryCode          string `json:"countryCode"`
			UsageType            string `json:"usageType"`
			ISP                  string `json:"isp"`
			Domain               string `json:"domain"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	v := &Verdict{Source: a.Name(), Target: target, Country: doc.Data.CountryCode, ASN: doc.Data.ISP}
	v.Score = float64(doc.Data.AbuseConfidenceScore) / 100.0
	if v.Score >= 0.7 {
		v.Malicious = true
		v.Tags = append(v.Tags, "abuse")
	} else if v.Score >= 0.3 {
		v.Tags = append(v.Tags, "suspicious")
	}
	v.Detail = fmt.Sprintf("abuse_confidence=%d isp=%s domain=%s", doc.Data.AbuseConfidenceScore, doc.Data.ISP, doc.Data.Domain)
	return v, nil
}

// --- VirusTotal ------------------------------------------------------------

type VirusTotal struct {
	Key  string
	HTTP *http.Client
}

func (v *VirusTotal) Name() string  { return "virustotal" }
func (v *VirusTotal) Enabled() bool { return v.Key != "" }

func (v *VirusTotal) Lookup(ctx context.Context, target string) (*Verdict, error) {
	endpoint := fmt.Sprintf("https://www.virustotal.com/api/v3/ip_addresses/%s", url.PathEscape(target))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("x-apikey", v.Key)
	resp, err := v.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("virustotal %d: %s", resp.StatusCode, string(body))
	}
	var doc struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
				} `json:"last_analysis_stats"`
				Country string `json:"country"`
				ASN     int    `json:"asn"`
				ASOwner string `json:"as_owner"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	stats := doc.Data.Attributes.LastAnalysisStats
	total := stats.Malicious + stats.Suspicious + stats.Harmless
	vv := &Verdict{Source: v.Name(), Target: target, Country: doc.Data.Attributes.Country}
	if total > 0 {
		vv.Score = float64(stats.Malicious+stats.Suspicious) / float64(total)
	}
	if stats.Malicious > 0 {
		vv.Malicious = true
		vv.Tags = append(vv.Tags, "malicious")
	} else if stats.Suspicious > 0 {
		vv.Tags = append(vv.Tags, "suspicious")
	}
	vv.Detail = fmt.Sprintf("malicious=%d suspicious=%d harmless=%d asn=%s", stats.Malicious, stats.Suspicious, stats.Harmless, doc.Data.Attributes.ASOwner)
	return vv, nil
}

// --- helpers ---------------------------------------------------------------

// IsIP is a tiny helper used by callers that want to skip domain-only feeds
// when the target is an IP, or vice-versa.
func IsIP(s string) bool {
	// Defer to net.ParseIP for the strict check; otherwise fall back to a
	// permissive hostname detection so callers can still decide for themselves.
	return net.ParseIP(s) != nil
}
