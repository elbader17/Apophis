package poc

import (
	"crypto/hmac"
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

const auditSchemaVersion = "apophis-audit-v1"

type AuditLog struct {
	mu       sync.Mutex
	dir      string
	key      []byte
	readKey  []byte
	notifier func(string)
}

func OpenAuditLog(dir, keyPath string) (*AuditLog, error) {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	return &AuditLog{dir: dir, key: key, readKey: key}, nil
}

func (a *AuditLog) WithReadKey(k []byte) *AuditLog {
	a.readKey = k
	return a
}

func loadOrCreateKey(path string) ([]byte, error) {
	if path == "" {
		return randomKey(), nil
	}
	if b, err := os.ReadFile(path); err == nil {
		if len(b) == 32 {
			return b, nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	k := randomKey()
	if err := os.WriteFile(path, k, 0600); err != nil {
		return nil, err
	}
	return k, nil
}

func randomKey() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(time.Now().UnixNano() >> (i % 8))
	}
	sum := sha256.Sum256(b)
	return sum[:]
}

func (a *AuditLog) Dir() string { return a.dir }

func (a *AuditLog) Append(rec *AuditRecord) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if rec.ID == "" {
		rec.ID = fmt.Sprintf("exe-%d", time.Now().UnixNano())
	}
	rec.HMAC = ""
	canonical, err := canonicalBytes(rec)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, a.key)
	mac.Write(canonical)
	rec.HMAC = hex.EncodeToString(mac.Sum(nil))
	body, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", err
	}
	if v := os.Getenv("APOPHIS_DEBUG_HMAC"); v != "" {
		fmt.Fprintf(os.Stderr, "DEBUG append id=%s hmac=%s\n", rec.ID, rec.HMAC)
	}
	path := filepath.Join(a.dir, rec.ID+".json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, body, 0444); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, path); err != nil {
		return "", err
	}
	return rec.ID, nil
}

func (a *AuditLog) Read(id string) (*AuditRecord, error) {
	path := filepath.Join(a.dir, id+".json")
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var rec AuditRecord
	if err := json.Unmarshal(body, &rec); err != nil {
		return nil, err
	}
	stored := rec.HMAC
	if stored == "" {
		return &rec, fmt.Errorf("audit record %s: no HMAC present", id)
	}
	storedBytes, err := hex.DecodeString(stored)
	if err != nil {
		return &rec, fmt.Errorf("audit record %s: stored HMAC is not hex: %w", id, err)
	}
	rec.HMAC = ""
	canonical, err := canonicalBytes(&rec)
	if err != nil {
		return nil, err
	}
	mac := hmac.New(sha256.New, a.readKey)
	mac.Write(canonical)
	if !hmac.Equal(mac.Sum(nil), storedBytes) {
		rec.HMAC = stored
		return &rec, fmt.Errorf("audit record %s: HMAC mismatch (tampered)", id)
	}
	rec.HMAC = stored
	return &rec, nil
}

func canonicalBytes(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	delete(out, "hmac")
	return json.Marshal(out)
}

func bodyHMAC(body []byte) string {
	var probe struct {
		HMAC string `json:"hmac"`
	}
	_ = json.Unmarshal(body, &probe)
	return probe.HMAC
}

var _ = auditSchemaVersion

func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, err
	}
	delete(out, "hmac")
	keys := make([]string, 0, len(out))
	for k := range out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var sb strings.Builder
	sb.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			sb.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, _ := json.Marshal(out[k])
		sb.Write(kb)
		sb.WriteByte(':')
		sb.Write(vb)
	}
	sb.WriteByte('}')
	return []byte(sb.String()), nil
}

func (a *AuditLog) List(since time.Time, target string, limit int) ([]AuditMeta, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ents, err := os.ReadDir(a.dir)
	if err != nil {
		return nil, err
	}
	out := []AuditMeta{}
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(ent.Name(), ".json")
		rec, err := a.readNoLock(id)
		if err != nil {
			continue
		}
		if !since.IsZero() && rec.StartedAt.Before(since) {
			continue
		}
		if target != "" && rec.Target != target {
			continue
		}
		out = append(out, AuditMeta{
			ID:              rec.ID,
			StartedAt:       rec.StartedAt,
			DurationMs:      rec.DurationMs,
			Target:          rec.Target,
			PoCID:           rec.PoC.ID,
			PoCCVE:          rec.PoC.CVE,
			Risk:            rec.PoC.Risk,
			Sandbox:         rec.Sandbox.Level,
			ExitCode:        rec.ExitCode,
			ExploitVerified: rec.ExploitVerified,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].StartedAt.After(out[j].StartedAt) })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (a *AuditLog) readNoLock(id string) (*AuditRecord, error) {
	body, err := os.ReadFile(filepath.Join(a.dir, id+".json"))
	if err != nil {
		return nil, err
	}
	var r AuditRecord
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

type AuditMeta struct {
	ID              string    `json:"id"`
	StartedAt       time.Time `json:"started_at"`
	DurationMs      int64     `json:"duration_ms"`
	Target          string    `json:"target"`
	PoCID           string    `json:"poc_id"`
	PoCCVE          string    `json:"poc_cve"`
	Risk            string    `json:"risk"`
	Sandbox         string    `json:"sandbox"`
	ExitCode        int       `json:"exit_code"`
	ExploitVerified bool      `json:"exploit_verified"`
}
