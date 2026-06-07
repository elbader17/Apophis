// Package sources contains adapters for public vulnerability databases
// that the Apophis research agent consumes. It also defines the unified
// Finding type that all sources produce.
package sources

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
)

// Finding is the unified, normalized representation of a vulnerability
// discovered by a research source, regardless of which source produced it.
type Finding struct {
	Source      string          `json:"source"`
	CVE         string          `json:"cve"`
	Title       string          `json:"title"`
	Description string          `json:"description"`
	Severity    models.Severity `json:"severity"`
	CVSS        float64         `json:"cvss"`
	Published   time.Time       `json:"published"`
	Modified    time.Time       `json:"modified"`
	Vendors     []string        `json:"vendors"`
	Products    []string        `json:"products"`
	ExploitURLs []string        `json:"exploit_urls"`
	References  []string        `json:"references"`
	ExploitCode string          `json:"exploit_code,omitempty"`
	HasKEV      bool            `json:"kev"`
	Remediation string          `json:"remediation"`
}

// ToCVEEntry converts a Finding to the dynamic database entry used by the
// matcher.
func (f Finding) ToCVEEntry() dynamic.Entry {
	svc, ver := bestSignature(f)
	sev := f.Severity
	if sev == "" {
		sev = cvssToSev(f.CVSS)
	}
	exploit := f.ExploitCode
	if exploit == "" && len(f.ExploitURLs) > 0 {
		exploit = "Public PoC available. See references."
	}
	if exploit == "" {
		exploit = "Use apophis_research to fetch the latest PoC, or consult Exploit-DB / GitHub Security Advisory."
	}
	desc := f.Description
	if desc == "" {
		desc = f.Title
	}
	remed := f.Remediation
	if remed == "" {
		remed = "Apply vendor patch. Restrict exposure until patched."
	}
	refs := f.References
	if len(f.ExploitURLs) > 0 {
		refs = append(refs, f.ExploitURLs...)
	}
	return dynamic.Entry{
		CVE:         f.CVE,
		Service:     svc,
		Version:     ver,
		Severity:    string(sev),
		CVSS:        f.CVSS,
		Title:       f.Title,
		Description: desc,
		Exploit:     exploit,
		Remediation: remed,
		References:  refs,
		Source:      f.Source,
		Published:   f.Published,
		HasKEV:      f.HasKEV,
	}
}

func bestSignature(f Finding) (service, version string) {
	if len(f.Products) > 0 {
		service = strings.ToLower(f.Products[0])
	}
	if service == "" && len(f.Vendors) > 0 {
		service = strings.ToLower(f.Vendors[0])
	}
	if service == "" {
		service = strings.ToLower(strings.SplitN(f.Title, " ", 2)[0])
	}
	version = "*"
	return
}

func cvssToSev(v float64) models.Severity {
	switch {
	case v >= 9.0:
		return models.SeverityCritical
	case v >= 7.0:
		return models.SeverityHigh
	case v >= 4.0:
		return models.SeverityMedium
	case v > 0:
		return models.SeverityLow
	}
	return models.SeverityInfo
}

// Source is the interface every research source implements.
type Source interface {
	Name() string
	Fetch(ctx SourceContext) ([]Finding, error)
}

type SourceContext struct {
	Since    time.Time
	MaxItems int
}

// Dedupe merges findings by CVE id, preferring higher CVSS / more data.
func Dedupe(in []Finding) []Finding {
	idx := map[string]int{}
	out := []Finding{}
	for _, f := range in {
		key := f.CVE
		if key == "" {
			key = fmt.Sprintf("%s|%s", f.Source, f.Title)
		}
		if i, ok := idx[key]; ok {
			out[i] = mergeFinding(out[i], f)
			continue
		}
		idx[key] = len(out)
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CVSS != out[j].CVSS {
			return out[i].CVSS > out[j].CVSS
		}
		return out[i].Published.After(out[j].Published)
	})
	return out
}

func mergeFinding(a, b Finding) Finding {
	if a.CVE == "" {
		a.CVE = b.CVE
	}
	if a.Title == "" {
		a.Title = b.Title
	}
	if a.Description == "" {
		a.Description = b.Description
	}
	if a.CVSS < b.CVSS {
		a.CVSS = b.CVSS
	}
	if a.Severity == "" {
		a.Severity = b.Severity
	}
	if a.Published.IsZero() || (!b.Published.IsZero() && b.Published.Before(a.Published)) {
		a.Published = b.Published
	}
	if a.Modified.Before(b.Modified) {
		a.Modified = b.Modified
	}
	a.Vendors = uniqStr(append(a.Vendors, b.Vendors...))
	a.Products = uniqStr(append(a.Products, b.Products...))
	a.ExploitURLs = uniqStr(append(a.ExploitURLs, b.ExploitURLs...))
	a.References = uniqStr(append(a.References, b.References...))
	if a.ExploitCode == "" {
		a.ExploitCode = b.ExploitCode
	}
	a.HasKEV = a.HasKEV || b.HasKEV
	if a.Remediation == "" {
		a.Remediation = b.Remediation
	}
	return a
}

func uniqStr(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
