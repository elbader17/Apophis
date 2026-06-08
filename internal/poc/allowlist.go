package poc

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
)

type allowEntry struct {
	raw  string
	cidr *net.IPNet
	ip   net.IP
	host string
	note string
}

type Allowlist struct {
	mu      sync.RWMutex
	entries []allowEntry
	extra   []allowEntry
}

func NewAllowlist() *Allowlist { return &Allowlist{} }

func parseEntry(line string) (allowEntry, error) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return allowEntry{}, fmt.Errorf("empty line")
	}
	raw := parts[0]
	if len(parts) > 1 {
		for _, p := range parts[1:] {
			if strings.HasPrefix(p, "#") {
				break
			}
		}
	}
	note := ""
	if len(parts) > 1 {
		cleaned := []string{}
		for _, p := range parts[1:] {
			if strings.HasPrefix(p, "#") {
				break
			}
			cleaned = append(cleaned, p)
		}
		note = strings.Join(cleaned, " ")
	}
	e := allowEntry{raw: raw, note: note}

	if strings.Contains(raw, "/") {
		_, cidr, err := net.ParseCIDR(raw)
		if err != nil {
			return e, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		e.cidr = cidr
		return e, nil
	}
	if ip := net.ParseIP(raw); ip != nil {
		e.ip = ip
		return e, nil
	}
	if !isValidHostname(raw) {
		return e, fmt.Errorf("invalid target %q (not IP, CIDR, or valid hostname)", raw)
	}
	e.host = strings.ToLower(raw)
	return e, nil
}

func isValidHostname(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if strings.HasSuffix(h, ".") {
		h = h[:len(h)-1]
	}
	for _, label := range strings.Split(h, ".") {
		if label == "" || len(label) > 63 {
			return false
		}
		for _, c := range label {
			if !(c == '-' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
				return false
			}
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func LoadAllowlistFile(path string) (*Allowlist, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open allowlist: %w", err)
	}
	defer f.Close()
	al := NewAllowlist()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, err := parseEntry(line)
		if err != nil {
			return nil, fmt.Errorf("allowlist line %q: %w", line, err)
		}
		al.entries = append(al.entries, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return al, nil
}

func (a *Allowlist) Add(target, note string) error {
	e, err := parseEntry(target + " " + note)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, ex := range a.entries {
		if ex.raw == e.raw {
			return fmt.Errorf("target %q already in allowlist", target)
		}
	}
	for _, ex := range a.extra {
		if ex.raw == e.raw {
			return fmt.Errorf("target %q already in allowlist", target)
		}
	}
	a.extra = append(a.extra, e)
	return nil
}

func (a *Allowlist) Remove(target string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for i, e := range a.entries {
		if e.raw == target {
			a.entries = append(a.entries[:i], a.entries[i+1:]...)
			return true
		}
	}
	for i, e := range a.extra {
		if e.raw == target {
			a.extra = append(a.extra[:i], a.extra[i+1:]...)
			return true
		}
	}
	return false
}

func (a *Allowlist) List() []string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := []string{}
	seen := map[string]bool{}
	for _, e := range a.entries {
		if !seen[e.raw] {
			seen[e.raw] = true
			if e.note != "" {
				out = append(out, e.raw+"\t"+e.note)
			} else {
				out = append(out, e.raw)
			}
		}
	}
	for _, e := range a.extra {
		if !seen[e.raw] {
			seen[e.raw] = true
			if e.note != "" {
				out = append(out, e.raw+"\t"+e.note)
			} else {
				out = append(out, e.raw)
			}
		}
	}
	sort.Strings(out)
	return out
}

func (a *Allowlist) Len() int {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return len(a.entries) + len(a.extra)
}

func (a *Allowlist) Contains(target string) (bool, string) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	all := append([]allowEntry{}, a.entries...)
	all = append(all, a.extra...)

	if ip := net.ParseIP(target); ip != nil {
		for _, e := range all {
			if e.ip != nil && e.ip.Equal(ip) {
				return true, e.note
			}
			if e.cidr != nil && e.cidr.Contains(ip) {
				return true, e.note
			}
		}
		return false, ""
	}

	host := strings.ToLower(strings.TrimSuffix(target, "."))
	if host == "" {
		return false, ""
	}
	for _, e := range all {
		if e.host != "" {
			if e.host == host {
				return true, e.note
			}
			if strings.HasSuffix(host, "."+e.host) {
				return true, e.note
			}
		}
	}
	if ips, err := net.LookupIP(host); err == nil {
		for _, ip := range ips {
			for _, e := range all {
				if e.ip != nil && e.ip.Equal(ip) {
					return true, e.note
				}
				if e.cidr != nil && e.cidr.Contains(ip) {
					return true, e.note
				}
			}
		}
	}
	return false, ""
}
