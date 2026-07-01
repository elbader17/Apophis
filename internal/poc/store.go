package poc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Store struct {
	mu  sync.RWMutex
	dir string
	idx map[string]string   // id -> file path
	byc map[string][]string // cve -> []id
}

func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	s := &Store{dir: dir, idx: map[string]string{}, byc: map[string][]string{}}
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
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return err
	}
	for id, path := range m {
		s.idx[id] = path
		rec, err := readPoC(path)
		if err != nil {
			continue
		}
		if rec.CVE != "" {
			s.byc[rec.CVE] = append(s.byc[rec.CVE], id)
		}
	}
	return nil
}

func (s *Store) saveIndex() error {
	idxPath := filepath.Join(s.dir, "index.json")
	b, err := json.MarshalIndent(s.idx, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(idxPath, b, 0644)
}

func (s *Store) Dir() string { return s.dir }

func (s *Store) Save(p *PoC) error {
	if p.ID == "" {
		sum := sha256.Sum256([]byte(p.Raw + p.Title + time.Now().Format(time.RFC3339Nano)))
		p.ID = "custom-" + hex.EncodeToString(sum[:])[:16]
	}
	if p.Signature == "" {
		p.Signature = Signature(p.Raw)
	}
	if p.CreatedAt.IsZero() {
		p.CreatedAt = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	path := filepath.Join(s.dir, p.ID+".json")
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	rawPath := filepath.Join(s.dir, p.ID+".raw")
	if err := os.WriteFile(rawPath, []byte(p.Raw), 0644); err != nil {
		return err
	}
	s.idx[p.ID] = path
	if p.CVE != "" {
		s.byc[p.CVE] = append(s.byc[p.CVE], p.ID)
	}
	return s.saveIndex()
}

func (s *Store) Get(id string) (*PoC, error) {
	s.mu.RLock()
	path, ok := s.idx[id]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("PoC %q not found", id)
	}
	return readPoC(path)
}

func (s *Store) GetByCVE(cve string) []*PoC {
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := s.byc[cve]
	out := make([]*PoC, 0, len(ids))
	for _, id := range ids {
		if p, err := s.Get(id); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func (s *Store) List(cve, source string, minRisk, maxRisk RiskLevel, limit int) []*PoC {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []*PoC{}
	for id := range s.idx {
		p, err := readPoC(s.idx[id])
		if err != nil {
			continue
		}
		if cve != "" && p.CVE != cve {
			continue
		}
		if source != "" && p.Source != source {
			continue
		}
		if minRisk >= 0 && p.Risk < minRisk {
			continue
		}
		if maxRisk >= 0 && p.Risk > maxRisk {
			continue
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Risk > out[j].Risk })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Store) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.idx)
}

func readPoC(path string) (*PoC, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p PoC
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	path, ok := s.idx[id]
	if !ok {
		return fmt.Errorf("PoC %q not found", id)
	}
	os.Remove(path)
	os.Remove(strings.TrimSuffix(path, ".json") + ".raw")
	delete(s.idx, id)
	return s.saveIndex()
}
