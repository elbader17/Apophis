// Package sources contains adapters for public vulnerability databases
// that the Apophis research agent consumes.
package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

// HTTPDoer abstracts http.Client for testing.
type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

// Client is a thin HTTP client wrapper that all sources share.
type Client struct {
	HTTP   HTTPDoer
	APIKey string
	UA     string
}

func NewClient(apiKey, ua string) *Client {
	if ua == "" {
		ua = "apophis-research/0.1"
	}
	return &Client{
		HTTP:   &http.Client{Timeout: 30 * time.Second},
		APIKey: apiKey,
		UA:     ua,
	}
}

func (c *Client) Get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UA)
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("http %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}
	return body, nil
}

func (c *Client) Post(ctx context.Context, u string, payload []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(string(payload)))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", c.UA)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return body, fmt.Errorf("http %d: %s", resp.StatusCode, string(body[:min(200, len(body))]))
	}
	return body, nil
}

// nvdResponse matches the relevant parts of the NVD CVE 2.0 API.
type nvdResponse struct {
	ResultsPerPage  int `json:"resultsPerPage"`
	StartIndex      int `json:"startIndex"`
	TotalResults    int `json:"totalResults"`
	Vulnerabilities []struct {
		CVE struct {
			ID           string    `json:"id"`
			Published    time.Time `json:"published"`
			LastModified time.Time `json:"lastModified"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics struct {
				CVSSMetricV31 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV31"`
				CVSSMetricV30 []struct {
					CVSSData struct {
						BaseScore    float64 `json:"baseScore"`
						BaseSeverity string  `json:"baseSeverity"`
					} `json:"cvssData"`
				} `json:"cvssMetricV30"`
				CVSSMetricV2 []struct {
					CVSSData struct {
						BaseScore float64 `json:"baseScore"`
					} `json:"cvssData"`
				} `json:"cvssMetricV2"`
			} `json:"metrics"`
			References []struct {
				URL    string   `json:"url"`
				Tags   []string `json:"tags"`
				Source string   `json:"source"`
			} `json:"references"`
			Weaknesses []struct {
				Description []struct {
					Value string `json:"value"`
				} `json:"description"`
			} `json:"weaknesses"`
		} `json:"cve"`
		Configurations []struct {
			Nodes []struct {
				CPEMatch []struct {
					Criteria string `json:"criteria"`
				} `json:"cpeMatch"`
			} `json:"nodes"`
		} `json:"configurations"`
	} `json:"vulnerabilities"`
}

type NVD struct{ Client *Client }

func (n *NVD) Name() string { return "nvd" }

func (n *NVD) Fetch(ctx SourceContext) ([]Finding, error) {
	c := n.Client
	if c == nil {
		c = NewClient("", "")
	}
	if ctx.MaxItems <= 0 {
		ctx.MaxItems = 50
	}

	u := "https://services.nvd.nist.gov/rest/json/cves/2.0"
	if !ctx.Since.IsZero() {
		q := url.Values{}
		q.Set("lastModStartDate", ctx.Since.UTC().Format(time.RFC3339))
		q.Set("lastModEndDate", time.Now().UTC().Format(time.RFC3339))
		q.Set("resultsPerPage", fmt.Sprintf("%d", ctx.MaxItems))
		u = "https://services.nvd.nist.gov/rest/json/cves/2.0?" + q.Encode()
	} else {
		u = fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=%d", ctx.MaxItems)
	}

	body, err := c.Get(ctxToCtx(ctx), u)
	if err != nil {
		return nil, fmt.Errorf("nvd: %w", err)
	}
	var r nvdResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("nvd decode: %w", err)
	}

	out := make([]Finding, 0, len(r.Vulnerabilities))
	for _, v := range r.Vulnerabilities {
		f := Finding{Source: "nvd", CVE: v.CVE.ID, Title: v.CVE.ID, Published: v.CVE.Published, Modified: v.CVE.LastModified}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				f.Description = d.Value
				break
			}
		}
		for _, m := range v.CVE.Metrics.CVSSMetricV31 {
			f.CVSS = m.CVSSData.BaseScore
			f.Severity = models.Severity(strings.ToUpper(m.CVSSData.BaseSeverity))
			break
		}
		if f.CVSS == 0 {
			for _, m := range v.CVE.Metrics.CVSSMetricV30 {
				f.CVSS = m.CVSSData.BaseScore
				f.Severity = models.Severity(strings.ToUpper(m.CVSSData.BaseSeverity))
				break
			}
		}
		if f.Severity == "" {
			f.Severity = cvssToSev(f.CVSS)
		}
		for _, ref := range v.CVE.References {
			f.References = append(f.References, ref.URL)
			for _, t := range ref.Tags {
				if t == "Exploit" || t == "Patch" || t == "Mitigation" {
					f.ExploitURLs = append(f.ExploitURLs, ref.URL)
				}
			}
		}
		for _, c := range v.Configurations {
			for _, n := range c.Nodes {
				for _, m := range n.CPEMatch {
					vendor, product := parseCPE(m.Criteria)
					if vendor != "" {
						f.Vendors = append(f.Vendors, vendor)
					}
					if product != "" {
						f.Products = append(f.Products, product)
					}
				}
			}
		}
		out = append(out, f)
	}
	return out, nil
}

func parseCPE(criteria string) (vendor, product string) {
	parts := splitFields(criteria, 12)
	if len(parts) >= 5 {
		return strings.ToLower(parts[3]), strings.ToLower(parts[4])
	}
	return "", ""
}

func splitFields(s string, n int) []string {
	out := []string{}
	start := 0
	count := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			out = append(out, s[start:i])
			start = i + 1
			count++
			if count == n {
				return out
			}
		}
	}
	out = append(out, s[start:])
	return out
}

func ctxToCtx(c SourceContext) context.Context {
	return context.Background()
}
