// Package dynamic provides a runtime CVE database that augments the static
// (compiled-in) database with entries fetched by the research agent.
package dynamic

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	CVE         string    `json:"cve"`
	Service     string    `json:"service"`
	Version     string    `json:"version"`
	Severity    string    `json:"severity"`
	CVSS        float64   `json:"cvss"`
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Exploit     string    `json:"exploit"`
	Remediation string    `json:"remediation"`
	References  []string  `json:"references"`
	Source      string    `json:"source"`
	Published   time.Time `json:"published"`
	HasKEV      bool      `json:"kev"`
}

type Store struct {
	path string
	mu   sync.RWMutex
	data []Entry
}

// baked entries are populated by an optional generated file (baked.go) that
// can be created by apophis_research. They are loaded into the Store on Open
// but not persisted back to disk (so updating the source is the only way to
// change baked entries).
var baked []Entry

func Open(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	s := &Store{path: filepath.Join(dir, "dynamic-cves.json")}
	if err := s.load(); err != nil {
		return nil, err
	}
	for _, e := range baked {
		if e.CVE != "" {
			s.data = append(s.data, e)
		}
	}
	sort.Slice(s.data, func(i, j int) bool {
		if s.data[i].CVSS != s.data[j].CVSS {
			return s.data[i].CVSS > s.data[j].CVSS
		}
		return s.data[i].Published.After(s.data[j].Published)
	})
	return s, nil
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(b, &s.data)
}

func (s *Store) save() error {
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0644)
}

func (s *Store) All() []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Entry, len(s.data))
	copy(out, s.data)
	return out
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.data)
}

func (s *Store) Add(entries []Entry) (added, updated int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := map[string]int{}
	for i, e := range s.data {
		idx[e.CVE] = i
	}
	for _, e := range entries {
		if e.CVE == "" {
			continue
		}
		if i, ok := idx[e.CVE]; ok {
			existing := s.data[i]
			if shouldReplace(existing, e) {
				s.data[i] = mergeEntry(existing, e)
				updated++
			}
		} else {
			s.data = append(s.data, e)
			idx[e.CVE] = len(s.data) - 1
			added++
		}
	}
	sort.Slice(s.data, func(i, j int) bool {
		if s.data[i].CVSS != s.data[j].CVSS {
			return s.data[i].CVSS > s.data[j].CVSS
		}
		return s.data[i].Published.After(s.data[j].Published)
	})
	_ = s.save()
	return
}

func shouldReplace(a, b Entry) bool {
	if b.CVSS > a.CVSS {
		return true
	}
	if !b.Published.IsZero() && a.Published.IsZero() {
		return true
	}
	if b.HasKEV && !a.HasKEV {
		return true
	}
	if len(b.References) > len(a.References) {
		return true
	}
	return false
}

func mergeEntry(a, b Entry) Entry {
	if b.CVSS > a.CVSS {
		a.CVSS = b.CVSS
	}
	if b.Severity != "" {
		a.Severity = b.Severity
	}
	if b.Description != "" && len(b.Description) > len(a.Description) {
		a.Description = b.Description
	}
	if b.Exploit != "" && b.Exploit != a.Exploit {
		a.Exploit = b.Exploit
	}
	if b.Remediation != "" {
		a.Remediation = b.Remediation
	}
	a.References = uniq(append(a.References, b.References...))
	a.HasKEV = a.HasKEV || b.HasKEV
	if b.Source != "" {
		a.Source = b.Source
	}
	if !b.Published.IsZero() {
		a.Published = b.Published
	}
	return a
}

func uniq(in []string) []string {
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

func (s *Store) Search(q SearchQuery) []Entry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Entry{}
	qLower := strings.ToLower(q.Keyword)
	for _, e := range s.data {
		if q.MinCVSS > 0 && e.CVSS < q.MinCVSS {
			continue
		}
		if q.Severity != "" && !strings.EqualFold(e.Severity, q.Severity) {
			continue
		}
		if q.OnlyKEV && !e.HasKEV {
			continue
		}
		if q.Since != nil && !e.Published.IsZero() && e.Published.Before(*q.Since) {
			continue
		}
		if q.Keyword != "" {
			hay := strings.ToLower(strings.Join([]string{e.CVE, e.Title, e.Description, e.Service, e.Version, strings.Join(e.References, " ")}, " "))
			if !strings.Contains(hay, qLower) {
				continue
			}
		}
		out = append(out, e)
		if q.Limit > 0 && len(out) >= q.Limit {
			break
		}
	}
	return out
}

type SearchQuery struct {
	Keyword  string
	MinCVSS  float64
	Severity string
	OnlyKEV  bool
	Since    *time.Time
	Limit    int
}

func (s *Store) Path() string { return s.path }

// Pretty returns a short human-readable listing.
func (s *Store) Pretty(limit int) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(s.data) == 0 {
		return "(empty)"
	}
	out := []string{}
	for i, e := range s.data {
		if limit > 0 && i >= limit {
			break
		}
		out = append(out, fmt.Sprintf("[%-8s] %s  CVSS=%.1f  %s", e.Severity, e.CVE, e.CVSS, truncate(e.Title, 70)))
	}
	return strings.Join(out, "\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
