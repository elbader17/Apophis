package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/apophis-eng/apophis/internal/models"
)

type Store struct {
	dir   string
	mu    sync.RWMutex
	index map[string]ReportMeta
}

type ReportMeta struct {
	ID          string    `json:"id"`
	Target      string    `json:"target"`
	URL         string    `json:"url"`
	GeneratedAt time.Time `json:"generated_at"`
	RiskScore   int       `json:"risk_score"`
	Critical    int       `json:"critical"`
	High        int       `json:"high"`
	Medium      int       `json:"medium"`
	Low         int       `json:"low"`
	Info        int       `json:"info"`
	Total       int       `json:"total"`
	Workers     int       `json:"workers"`
	Path        string    `json:"path"`
}

func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, index: map[string]ReportMeta{}}
	if err := s.loadIndex(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) loadIndex() error {
	idxPath := filepath.Join(s.dir, "index.json")
	b, err := os.ReadFile(idxPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	return json.Unmarshal(b, &s.index)
}

func (s *Store) saveIndex() error {
	idxPath := filepath.Join(s.dir, "index.json")
	b, err := json.MarshalIndent(s.index, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(idxPath, b, 0644)
}

func (s *Store) Save(r *models.Report) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id := fmt.Sprintf("rpt-%d", time.Now().UnixNano())
	path := filepath.Join(s.dir, id+".json")
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, b, 0644); err != nil {
		return "", err
	}

	mdPath := filepath.Join(s.dir, id+".md")
	if err := writeMD(mdPath, r); err != nil {
		return "", err
	}

	meta := ReportMeta{
		ID:          id,
		Target:      r.Target.Host,
		URL:         r.Target.URL,
		GeneratedAt: r.GeneratedAt,
		RiskScore:   r.Summary.RiskScore,
		Critical:    r.Summary.Critical,
		High:        r.Summary.High,
		Medium:      r.Summary.Medium,
		Low:         r.Summary.Low,
		Info:        r.Summary.Info,
		Total:       r.Summary.Total,
		Workers:     r.Workers,
		Path:        path,
	}
	s.index[id] = meta
	if err := s.saveIndex(); err != nil {
		return "", err
	}
	return id, nil
}

func (s *Store) Get(id string) (*models.Report, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	meta, ok := s.index[id]
	if !ok {
		return nil, fmt.Errorf("report %q not found", id)
	}
	b, err := os.ReadFile(meta.Path)
	if err != nil {
		return nil, err
	}
	var r models.Report
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	meta, ok := s.index[id]
	if !ok {
		return fmt.Errorf("report %q not found", id)
	}
	os.Remove(meta.Path)
	os.Remove(strings.TrimSuffix(meta.Path, ".json") + ".md")
	delete(s.index, id)
	return s.saveIndex()
}

func (s *Store) List(targetFilter string) []ReportMeta {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ReportMeta, 0, len(s.index))
	for _, m := range s.index {
		if targetFilter != "" && !strings.Contains(m.Target, targetFilter) {
			continue
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].GeneratedAt.After(out[j].GeneratedAt)
	})
	return out
}

func (s *Store) Dir() string { return s.dir }

func writeMD(path string, r *models.Report) error {
	header := fmt.Sprintf("# %s\n\nTarget: `%s`\nURL: `%s`\nGenerated: %s\nRisk: %d\n\nFindings: %d (C:%d H:%d M:%d L:%d I:%d)\n\nSee %s for full report.\n",
		r.Target.Host, r.Target.Host, r.Target.URL, r.GeneratedAt.Format(time.RFC3339),
		r.Summary.RiskScore, r.Summary.Total, r.Summary.Critical, r.Summary.High,
		r.Summary.Medium, r.Summary.Low, r.Summary.Info, filepath.Base(path))
	return os.WriteFile(path, []byte(header), 0644)
}
