package sources

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

)

type OSV struct{ Client *Client }

func (o *OSV) Name() string { return "osv" }

type osvQuery struct {
	ModifiedSince string `json:"modified_since,omitempty"`
	Package      struct {
		Name string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package,omitempty"`
}

type osvVuln struct {
	ID         string    `json:"id"`
	Summary    string    `json:"summary"`
	Details    string    `json:"details"`
	Modified   time.Time `json:"modified"`
	Published  time.Time `json:"published"`
	Aliases    []string  `json:"aliases"`
	Severity   []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Introduced string `json:"introduced,omitempty"`
				Fixed      string `json:"fixed,omitempty"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	References []struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"references"`
}

type osvQueryResp struct {
	Vulns []osvVuln `json:"vulns"`
}

func (o *OSV) Fetch(ctx SourceContext) ([]Finding, error) {
	c := o.Client
	if c == nil {
		c = NewClient("", "")
	}
	now := time.Now().UTC()
	since := ctx.Since
	if since.IsZero() {
		since = now.Add(-7 * 24 * time.Hour)
	}
	q := map[string]any{
		"modified_since": since.Format(time.RFC3339),
	}
	body, _ := json.Marshal(q)
	resp, err := c.Get(ctxToCtx(ctx), "https://api.osv.dev/v1/query")
	if err != nil {
		return nil, fmt.Errorf("osv: %w", err)
	}
	_ = resp
	body, err = c.Post(ctxToCtx(ctx), "https://api.osv.dev/v1/query", body)
	if err != nil {
		return nil, fmt.Errorf("osv post: %w", err)
	}
	var outResp osvQueryResp
	if err := json.Unmarshal(body, &outResp); err != nil {
		return nil, fmt.Errorf("osv decode: %w", err)
	}
	out := []Finding{}
	for _, v := range outResp.Vulns {
		f := Finding{
			Source:      "osv",
			CVE:         v.ID,
			Title:       v.Summary,
			Description: v.Details,
			Published:   v.Published,
			Modified:    v.Modified,
		}
		if f.Title == "" {
			f.Title = v.ID
		}
		for _, sev := range v.Severity {
			if sev.Type == "CVSS_V3" {
				score, _ := parseCVSSVector(sev.Score)
				if score > f.CVSS {
					f.CVSS = score
				}
			}
		}
		if f.CVSS == 0 {
			f.CVSS = 7.0
		}
		for _, a := range v.Aliases {
			if strings.HasPrefix(a, "CVE-") && a != v.ID {
				if !contains(f.References, "https://nvd.nist.gov/vuln/detail/"+a) {
					f.References = append(f.References, "https://nvd.nist.gov/vuln/detail/"+a)
				}
			}
		}
		for _, r := range v.References {
			if r.URL != "" {
				f.References = append(f.References, r.URL)
				if r.Type == "EXPLOIT" {
					f.ExploitURLs = append(f.ExploitURLs, r.URL)
				}
			}
		}
		for _, aff := range v.Affected {
			if aff.Package.Name != "" {
				f.Products = append(f.Products, aff.Package.Name)
			}
		}
		out = append(out, f)
		if ctx.MaxItems > 0 && len(out) >= ctx.MaxItems {
			break
		}
	}
	return out, nil
}

func parseCVSSVector(v string) (float64, error) {
	idx := strings.LastIndex(v, ":")
	if idx < 0 {
		return 0, nil
	}
	end := strings.IndexAny(v[idx:], " /")
	tail := v[idx+1:]
	if end > 0 {
		tail = tail[:end]
	}
	var f float64
	_, err := fmt.Sscanf(tail, "%f", &f)
	return f, err
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
