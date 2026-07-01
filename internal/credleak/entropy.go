package credleak

import (
	"fmt"
	"math"
	"regexp"

	"github.com/apophis-eng/apophis/internal/models"
)

// EntropyDetector scans an HTTP response body for high-entropy strings
// adjacent to credential-shaped keywords (password, api_key, secret, …).
// The detector is intentionally conservative: a positive match requires
// (a) a credential keyword, (b) a separator (= or :), (c) a value whose
// Shannon entropy is above a tunable threshold. This catches passwords
// in JS bundles, env dumps in stack traces, debug log leaks, etc.
type EntropyDetector struct {
	MinEntropy float64 // default 4.0
	MinLength  int     // default 12
}

// NewEntropyDetector returns a detector with sensible defaults.
func NewEntropyDetector() *EntropyDetector {
	return &EntropyDetector{MinEntropy: 4.0, MinLength: 12}
}

// credRe matches "key = value" / "key: value" where key looks credential-
// related and value is at least 8 chars. Value is captured.
var credRe = regexp.MustCompile(`(?i)(?:password|passwd|pwd|api[_-]?key|secret|token|access[_-]?key|auth[_-]?key|client[_-]?secret|private[_-]?key|session[_-]?key)\s*["':=]\s*["']?([A-Za-z0-9+/=_\-\.@!#$%^&*]{8,256})["']?`)

// Scan returns findings for every credential-shaped match whose entropy is
// above the threshold.
func (e *EntropyDetector) Scan(target, body string) []models.Finding {
	if body == "" {
		return nil
	}
	minEnt := e.MinEntropy
	if minEnt <= 0 {
		minEnt = 4.0
	}
	minLen := e.MinLength
	if minLen <= 0 {
		minLen = 12
	}
	findings := []models.Finding{}
	matches := credRe.FindAllStringSubmatch(body, -1)
	seen := map[string]bool{}
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		v := m[1]
		if len(v) < minLen || seen[v] {
			continue
		}
		ent := shannonEntropy(v)
		if ent < minEnt {
			continue
		}
		seen[v] = true
		findings = append(findings, F(
			VectorEntropyLeak,
			fmt.Sprintf("High-entropy credential-shaped value in HTTP response on %s", target),
			target,
			models.SeverityCritical,
			fmt.Sprintf("entropy=%.2f value_len=%d value_preview=%q", ent, len(v), preview(v)),
			"An HTTP response contains a high-entropy string next to a credential keyword (password, api_key, …). The value is a credential leaked through error pages, debug logs, or a forgotten API response field.",
			"curl the URL and grep for `password|secret|api_key`; capture the token from the response.",
			"Strip credentials from error responses, debug logs, and stack traces. Use allow-listed JSON response shapes. Never embed secrets in client-side JS bundles.",
		))
	}
	return findings
}

// shannonEntropy returns the Shannon entropy of `s` in bits per character.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := map[rune]int{}
	for _, r := range s {
		freq[r]++
	}
	n := float64(len(s))
	ent := 0.0
	for _, c := range freq {
		p := float64(c) / n
		ent -= p * math.Log2(p)
	}
	return ent
}

func preview(s string) string {
	if len(s) > 16 {
		return s[:8] + "..." + s[len(s)-4:]
	}
	return s
}
