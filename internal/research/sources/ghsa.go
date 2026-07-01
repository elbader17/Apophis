package sources

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

// GitHubAdvisory queries the GitHub GraphQL API for recent security advisories.
// It needs a GITHUB_TOKEN env var for > 60 req/h, but works unauthenticated
// at a reduced rate.
type GitHubAdvisory struct {
	Client *Client
	Token  string
}

func (g *GitHubAdvisory) Name() string { return "ghsa" }

type ghAdvisory struct {
	ID          string `json:"id"`
	DatabaseID  int    `json:"databaseId"`
	Identifiers []struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	} `json:"identifiers"`
	Description string    `json:"description"`
	Severity    string    `json:"severity"`
	PublishedAt time.Time `json:"publishedAt"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Summary     string    `json:"summary"`
	References  []struct {
		URL string `json:"url"`
	} `json:"references"`
	CVSS struct {
		Score        float64 `json:"score"`
		VectorString string  `json:"vectorString"`
	} `json:"cvss"`
}

type ghResp struct {
	Data struct {
		SecurityAdvisories []ghAdvisory `json:"securityAdvisories"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

func (g *GitHubAdvisory) Fetch(ctx SourceContext) ([]Finding, error) {
	c := g.Client
	if c == nil {
		c = NewClient("", "")
	}
	if ctx.MaxItems <= 0 {
		ctx.MaxItems = 30
	}
	since := ctx.Since
	if since.IsZero() {
		since = time.Now().Add(-7 * 24 * time.Hour)
	}
	query := fmt.Sprintf(`{"query":"{ securityAdvisories(updatedSince: \"%s\", first: %d, orderBy: {field: UPDATED_AT, direction: DESC}) { id databaseId identifiers { type value } description severity publishedAt updatedAt summary references { url } cvss { score vectorString } } }"}`,
		since.UTC().Format(time.RFC3339), ctx.MaxItems)
	body, err := c.Post(ctxToCtx(ctx), "https://api.github.com/graphql", []byte(query))
	if err != nil {
		return nil, fmt.Errorf("ghsa: %w", err)
	}
	if g.Token != "" {
		_ = strings.Contains(string(body), g.Token) // ignore
	}
	var r ghResp
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("ghsa decode: %w", err)
	}
	if len(r.Errors) > 0 {
		return nil, fmt.Errorf("ghsa api: %s", r.Errors[0].Message)
	}
	out := []Finding{}
	for _, a := range r.Data.SecurityAdvisories {
		f := Finding{
			Source:      "ghsa",
			Title:       a.Summary,
			Description: a.Description,
			Published:   a.PublishedAt,
			Modified:    a.UpdatedAt,
			CVSS:        a.CVSS.Score,
		}
		severity := strings.ToUpper(a.Severity)
		if severity == "" {
			severity = "MEDIUMIUM"
		}
		f.Severity = models.Severity(severity)
		if f.Title == "" {
			f.Title = a.ID
		}
		for _, id := range a.Identifiers {
			if id.Type == "CVE" {
				f.CVE = id.Value
			} else if id.Type == "GHSA" && f.CVE == "" {
				f.CVE = id.Value
			}
		}
		if f.CVE == "" {
			f.CVE = a.ID
		}
		for _, ref := range a.References {
			if ref.URL != "" {
				f.References = append(f.References, ref.URL)
			}
		}
		out = append(out, f)
	}
	return out, nil
}
