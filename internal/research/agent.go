// Package research contains the vulnerability-research agent that pulls CVEs
// and exploit PoCs from public security sources and integrates them into the
// local CVE database (and the generated check/exploit stubs).
package research

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/apophis-eng/apophis/internal/logger"
	"github.com/apophis-eng/apophis/internal/research/sources"
	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
)

// Agent orchestrates the vulnerability research. It runs each registered
// source in parallel, deduplicates the results, persists them to the
// dynamic store, and (optionally) emits generated Go check stubs.
type Agent struct {
	Dynamic *dynamic.Store
	Sources []sources.Source
	NVDKey  string
	GHToken string
}

type SyncResult struct {
	StartedAt    time.Time    `json:"started_at"`
	FinishedAt   time.Time    `json:"finished_at"`
	Duration     string       `json:"duration"`
	SourceStats  []SourceStat `json:"source_stats"`
	TotalFetched int          `json:"total_fetched"`
	AfterDedup   int          `json:"after_dedup"`
	Added        int          `json:"added"`
	Updated      int          `json:"updated"`
	TopFindings  []string     `json:"top_findings"`
}

type SourceStat struct {
	Name    string `json:"name"`
	Fetched int    `json:"fetched"`
	Error   string `json:"error,omitempty"`
}

func New(dynamicStore *dynamic.Store, nvdKey, ghToken string) *Agent {
	c := sources.NewClient(nvdKey, "apophis-research/0.1")
	return &Agent{
		Dynamic: dynamicStore,
		NVDKey:  nvdKey,
		GHToken: ghToken,
		Sources: []sources.Source{
			&sources.NVD{Client: c},
			&sources.KEV{Client: c},
			&sources.OSV{Client: c},
			&sources.ExploitDB{Client: c},
			&sources.GitHubAdvisory{Client: c, Token: ghToken},
			&sources.RSSAdapter{SourceName: "securityweek", URL: "https://www.securityweek.com/feed/", Client: c},
			&sources.RSSAdapter{SourceName: "thehackernews", URL: "https://thehackernews.com/feeds/posts/default", Client: c},
			&sources.RSSAdapter{SourceName: "packetstorm", URL: "https://rss.packetstormsecurity.org/news/", Client: c},
		},
	}
}

func (a *Agent) SourcesByName(names []string) []sources.Source {
	if len(names) == 0 {
		return a.Sources
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	out := []sources.Source{}
	for _, s := range a.Sources {
		if want[s.Name()] {
			out = append(out, s)
		}
	}
	return out
}

func (a *Agent) Names() []string {
	out := make([]string, 0, len(a.Sources))
	for _, s := range a.Sources {
		out = append(out, s.Name())
	}
	return out
}

// Sync runs all selected sources in parallel, deduplicates and persists.
func (a *Agent) Sync(ctx context.Context, selected []string, since time.Time, maxPerSource int) (*SyncResult, error) {
	startedAt := time.Now()
	res := &SyncResult{StartedAt: startedAt}

	srcs := a.SourcesByName(selected)
	logger.Info("apophis-research", fmt.Sprintf("syncing %d sources (since=%s, max/source=%d)", len(srcs), since.Format(time.RFC3339), maxPerSource))

	var (
		mu      sync.Mutex
		allFind []sources.Finding
		wg      sync.WaitGroup
	)
	for _, s := range srcs {
		wg.Add(1)
		go func(s sources.Source) {
			defer wg.Done()
			findings, err := s.Fetch(sources.SourceContext{Since: since, MaxItems: maxPerSource})
			stat := SourceStat{Name: s.Name(), Fetched: len(findings)}
			if err != nil {
				stat.Error = err.Error()
				logger.Warn("apophis-research", fmt.Sprintf("%s: %s", s.Name(), err))
			} else {
				logger.Info("apophis-research", fmt.Sprintf("%s: %d findings", s.Name(), len(findings)))
			}
			mu.Lock()
			res.SourceStats = append(res.SourceStats, stat)
			if err == nil {
				allFind = append(allFind, findings...)
				res.TotalFetched += len(findings)
			}
			mu.Unlock()
		}(s)
	}
	wg.Wait()

	res.FinishedAt = time.Now()
	res.Duration = res.FinishedAt.Sub(startedAt).Round(time.Millisecond).String()

	deduped := sources.Dedupe(allFind)
	res.AfterDedup = len(deduped)

	entries := make([]dynamic.Entry, 0, len(deduped))
	for _, f := range deduped {
		entries = append(entries, f.ToCVEEntry())
	}
	res.Added, res.Updated = a.Dynamic.Add(entries)

	for _, f := range deduped {
		if f.CVSS >= 9.0 || f.HasKEV {
			res.TopFindings = append(res.TopFindings, fmt.Sprintf("[%s] %s — %s (CVSS %.1f)", f.Source, f.CVE, f.Title, f.CVSS))
		}
	}
	sort.Strings(res.TopFindings)
	if len(res.TopFindings) > 20 {
		res.TopFindings = res.TopFindings[:20]
	}

	logger.Success("apophis-research", fmt.Sprintf("done: fetched=%d dedup=%d added=%d updated=%d in %s",
		res.TotalFetched, res.AfterDedup, res.Added, res.Updated, res.Duration))
	return res, nil
}
