package sources

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type KEV struct{ Client *Client }

func (k *KEV) Name() string { return "cisa-kev" }

// CISA KEV feed uses a custom date format ("2024-01-01") plus an optional
// trailing time. We parse it manually.
type kevDate struct{ time.Time }

func (d *kevDate) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	for _, layout := range []string{"2006-01-02", "2006-01-02T15:04:05Z", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			d.Time = t
			return nil
		}
	}
	return fmt.Errorf("unparseable date: %q", s)
}

type kevDoc struct {
	Title           string    `json:"title"`
	CatalogVersion  string    `json:"catalogVersion"`
	DateReleased    kevDate   `json:"dateReleased"`
	Count           int       `json:"count"`
	Vulnerabilities []struct {
		CVEID             string  `json:"cveID"`
		VendorProject     string  `json:"vendorProject"`
		Product           string  `json:"product"`
		VulnerabilityName string  `json:"vulnerabilityName"`
		DateAdded         kevDate `json:"dateAdded"`
		ShortDescription  string  `json:"shortDescription"`
		RequiredAction    string  `json:"requiredAction"`
		DueDate           kevDate `json:"dueDate"`
		KnownRansomware   string  `json:"knownRansomwareCampaignUse"`
		Notes             string  `json:"notes"`
	} `json:"vulnerabilities"`
}

func (k *KEV) Fetch(ctx SourceContext) ([]Finding, error) {
	c := k.Client
	if c == nil {
		c = NewClient("", "")
	}
	body, err := c.Get(ctxToCtx(ctx), "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
	if err != nil {
		return nil, fmt.Errorf("kev: %w", err)
	}
	var d kevDoc
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("kev decode: %w", err)
	}
	out := []Finding{}
	for _, v := range d.Vulnerabilities {
		f := Finding{
			Source:      "cisa-kev",
			CVE:         v.CVEID,
			Title:       v.VulnerabilityName,
			Description: v.ShortDescription,
			HasKEV:      true,
			Published:   v.DateAdded.Time,
			Vendors:     []string{strings.ToLower(v.VendorProject)},
			Products:    []string{strings.ToLower(v.Product)},
			Remediation: v.RequiredAction,
			Severity:    "CRITICAL",
			CVSS:        9.8,
			References:  []string{fmt.Sprintf("https://nvd.nist.gov/vuln/detail/%s", v.CVEID)},
		}
		if v.KnownRansomware == "Known" {
			f.Title = "[RANSOMWARE] " + f.Title
		}
		out = append(out, f)
		if ctx.MaxItems > 0 && len(out) >= ctx.MaxItems {
			break
		}
	}
	return out, nil
}
