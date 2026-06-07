package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/apophis-eng/apophis/internal/logger"
	"github.com/apophis-eng/apophis/internal/models"
	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
	"github.com/apophis-eng/apophis/internal/worker"
)

type Orchestrator struct {
	Target      models.Target
	WorkerCount int
	Strategies  []models.Strategy
	Dynamic     *dynamic.Store
}

func New(target models.Target, workerCount int) *Orchestrator {
	if workerCount <= 0 {
		workerCount = 6
	}
	strategies := buildStrategies(workerCount)
	return &Orchestrator{
		Target:      target,
		WorkerCount: workerCount,
		Strategies:  strategies,
	}
}

func buildStrategies(n int) []models.Strategy {
	pool := []models.Strategy{
		models.StrategyRecon,
		models.StrategyAggressive,
		models.StrategyStealth,
		models.StrategyWebFocus,
		models.StrategyNetFocus,
		models.StrategyAuthFocus,
	}
	if n > len(pool) {
		for i := 0; i < n-len(pool); i++ {
			pool = append(pool, models.StrategyAggressive)
		}
	}
	return pool[:n]
}

func (o *Orchestrator) ForceStrategy(s models.Strategy) error {
	switch s {
	case models.StrategyRecon, models.StrategyAggressive, models.StrategyStealth,
		models.StrategyWebFocus, models.StrategyNetFocus, models.StrategyAuthFocus:
		strategies := make([]models.Strategy, o.WorkerCount)
		for i := range strategies {
			strategies[i] = s
		}
		o.Strategies = strategies
		return nil
	}
	return fmt.Errorf("unknown strategy: %s", s)
}

func (o *Orchestrator) Run(ctx context.Context) (*models.Report, error) {
	logger.Info("APOPHIS", fmt.Sprintf("summoning %d parallel agents against %s", o.WorkerCount, o.Target.Host))
	start := time.Now()

	results := make(chan worker.Result, o.WorkerCount)
	portSem := make(chan struct{}, 1)

	var wg sync.WaitGroup
	for i := 0; i < o.WorkerCount; i++ {
		w := &worker.Worker{
			ID:       worker.NewID("chaos"),
			Strategy: o.Strategies[i],
		}
		wg.Add(1)
		go func(wk *worker.Worker) {
			defer wg.Done()
			res := wk.Run(ctx, o.Target, portSem)
			results <- res
		}(w)
	}

	wg.Wait()
	close(results)

	allFindings := []models.Finding{}
	allPorts := []models.PortInfo{}
	allHTTP := []models.HTTPInfo{}
	var totalDuration time.Duration
	for r := range results {
		allFindings = append(allFindings, r.Findings...)
		allPorts = append(allPorts, r.Ports...)
		allHTTP = append(allHTTP, r.HTTPInfo...)
		if r.Duration > totalDuration {
			totalDuration = r.Duration
		}
	}

	allFindings = mergeAndDedupe(allFindings)
	allPorts = mergePorts(allPorts)
	allHTTP = mergeHTTP(allHTTP)

	summary := buildSummary(allFindings)

	report := &models.Report{
		Target:        o.Target,
		GeneratedAt:   time.Now(),
		Duration:      time.Since(start).Round(time.Millisecond).String(),
		Workers:       o.WorkerCount,
		TotalChecks:   o.WorkerCount * 5,
		Findings:      allFindings,
		Summary:       summary,
		PortScan:      allPorts,
		HTTPDiscovery: allHTTP,
	}

	logger.Info("APOPHIS", fmt.Sprintf("chaos complete in %s — %d findings (%d critical, %d high, %d medium)",
		report.Duration, summary.Total, summary.Critical, summary.High, summary.Medium))
	return report, nil
}

func mergeAndDedupe(findings []models.Finding) []models.Finding {
	idx := map[string]int{}
	out := []models.Finding{}
	for _, f := range findings {
		k := dedupKey(f)
		if i, ok := idx[k]; ok {
			if f.CVSS > out[i].CVSS {
				out[i].CVSS = f.CVSS
			}
			if len(f.References) > len(out[i].References) {
				out[i].References = f.References
			}
			if f.WorkerID != "" {
				out[i].References = append(out[i].References, fmt.Sprintf("detected by %s via %s", f.WorkerID, f.Strategy))
			}
			continue
		}
		idx[k] = len(out)
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].Severity.Score() > out[j].Severity.Score()
	})
	return out
}

func dedupKey(f models.Finding) string {
	return fmt.Sprintf("%s|%s|%s|%d", f.Category, f.Target, f.Title, f.Port)
}

func mergePorts(ports []models.PortInfo) []models.PortInfo {
	seen := map[int]bool{}
	out := []models.PortInfo{}
	for _, p := range ports {
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Port < out[j].Port })
	return out
}

func mergeHTTP(httpInfos []models.HTTPInfo) []models.HTTPInfo {
	seen := map[string]bool{}
	out := []models.HTTPInfo{}
	for _, h := range httpInfos {
		if seen[h.URL] {
			continue
		}
		seen[h.URL] = true
		out = append(out, h)
	}
	return out
}

func buildSummary(findings []models.Finding) models.Summary {
	s := models.Summary{}
	for _, f := range findings {
		s.Total++
		switch f.Severity {
		case models.SeverityCritical:
			s.Critical++
		case models.SeverityHigh:
			s.High++
		case models.SeverityMedium:
			s.Medium++
		case models.SeverityLow:
			s.Low++
		case models.SeverityInfo:
			s.Info++
		}
	}
	s.RiskScore = s.Critical*10 + s.High*7 + s.Medium*4 + s.Low*2
	return s
}
