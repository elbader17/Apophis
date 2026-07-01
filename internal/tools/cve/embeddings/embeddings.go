// Package embeddings provides a small in-process vector index over the CVE
// database. We use a TF-IDF + cosine similarity scheme: tokenize the title,
// description and references of each entry, weight each token by its inverse
// document frequency, and store the resulting L2-normalised vector.
//
// The package is deliberately dependency-free. It is not a replacement for a
// real embedding model — it is a small, fast, predictable index that gives
// "find me CVEs similar to this text" without needing any external service.
package embeddings

import (
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
)

const dimCap = 8192

// Index is the in-memory TF-IDF index.
type Index struct {
	mu      sync.RWMutex
	entries []dynamic.Entry
	// vocab maps token → column index in the sparse vector space.
	vocab map[string]int
	// idf[tokenIndex] = inverse document frequency.
	idf []float64
	// vectors[i] = normalised TF-IDF vector for entries[i].
	vectors [][]float64
	// norms[i] = L2 norm of vectors[i] (always 1 after normalisation; kept
	// for future use where vectors may be non-normalised).
	norms []float64
}

func New() *Index {
	return &Index{vocab: map[string]int{}}
}

// Rebuild re-computes the index from the provided entries. Idempotent and
// safe to call repeatedly; cheap enough to run after every research sync.
func (ix *Index) Rebuild(entries []dynamic.Entry) {
	ix.mu.Lock()
	defer ix.mu.Unlock()
	ix.entries = entries
	if len(entries) == 0 {
		ix.vocab = map[string]int{}
		ix.idf = nil
		ix.vectors = nil
		ix.norms = nil
		return
	}
	// 1) tokenise each entry, collect doc-frequency counts.
	tokens := make([][]string, len(entries))
	df := map[string]int{}
	for i, e := range entries {
		tokens[i] = tokenise(textOf(e))
		for _, t := range uniq(tokens[i]) {
			df[t]++
		}
	}
	// 2) build vocab from the union of tokens. Cap to dimCap most-frequent
	// tokens to keep vectors small.
	freq := make([]struct {
		tok string
		f   int
	}, 0, len(df))
	for t, f := range df {
		freq = append(freq, struct {
			tok string
			f   int
		}{t, f})
	}
	sort.Slice(freq, func(i, j int) bool {
		if freq[i].f != freq[j].f {
			return freq[i].f > freq[j].f
		}
		return freq[i].tok < freq[j].tok
	})
	if len(freq) > dimCap {
		freq = freq[:dimCap]
	}
	ix.vocab = make(map[string]int, len(freq))
	ix.idf = make([]float64, len(freq))
	for i, kv := range freq {
		ix.vocab[kv.tok] = i
		ix.idf[i] = math.Log(float64(1+len(entries)) / float64(1+kv.f))
	}
	// 3) build sparse → dense vectors and L2-normalise.
	ix.vectors = make([][]float64, len(entries))
	ix.norms = make([]float64, len(entries))
	for i, toks := range tokens {
		tf := map[string]int{}
		for _, t := range toks {
			if _, ok := ix.vocab[t]; !ok {
				continue
			}
			tf[t]++
		}
		v := make([]float64, len(ix.vocab))
		for t, c := range tf {
			v[ix.vocab[t]] = float64(c) * ix.idf[ix.vocab[t]]
		}
		n := l2(v)
		if n > 0 {
			for j := range v {
				v[j] /= n
			}
			ix.norms[i] = 1
		}
		ix.vectors[i] = v
	}
}

// Search returns the top-k most similar entries to the query text.
func (ix *Index) Search(query string, k int) []Result {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	if k <= 0 || len(ix.entries) == 0 {
		return nil
	}
	toks := tokenise(query)
	tf := map[string]int{}
	for _, t := range toks {
		if _, ok := ix.vocab[t]; !ok {
			continue
		}
		tf[t]++
	}
	v := make([]float64, len(ix.vocab))
	for t, c := range tf {
		v[ix.vocab[t]] = float64(c) * ix.idf[ix.vocab[t]]
	}
	n := l2(v)
	if n > 0 {
		for j := range v {
			v[j] /= n
		}
	}
	scores := make([]float64, len(ix.entries))
	for i := range ix.entries {
		scores[i] = dot(v, ix.vectors[i])
	}
	idx := make([]int, len(ix.entries))
	for i := range idx {
		idx[i] = i
	}
	sort.SliceStable(idx, func(i, j int) bool {
		return scores[idx[i]] > scores[idx[j]]
	})
	out := make([]Result, 0, k)
	for _, i := range idx {
		if scores[i] <= 0 {
			break
		}
		if len(out) >= k {
			break
		}
		out = append(out, Result{Entry: ix.entries[i], Score: scores[i]})
	}
	return out
}

type Result struct {
	Entry dynamic.Entry `json:"entry"`
	Score float64       `json:"score"`
}

func (ix *Index) Len() int {
	ix.mu.RLock()
	defer ix.mu.RUnlock()
	return len(ix.entries)
}

// --- tokenisation -----------------------------------------------------------

var (
	tokenRe = regexp.MustCompile(`[A-Za-z][A-Za-z0-9_\-]+`)
	cveRe   = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)
	stop    = map[string]bool{
		"the": true, "and": true, "or": true, "of": true, "to": true,
		"in": true, "for": true, "is": true, "on": true, "with": true,
		"that": true, "an": true, "a": true, "this": true, "by": true,
		"as": true, "are": true, "be": true, "from": true, "at": true,
		"allows": true, "remote": true, "attacker": true, "via": true,
	}
)

func tokenise(s string) []string {
	lower := strings.ToLower(s)
	// First extract any CVE ids as a single token (so CVE-2021-44228 is its
	// own dimension).
	out := []string{}
	for _, m := range cveRe.FindAllString(lower, -1) {
		out = append(out, m)
	}
	for _, m := range tokenRe.FindAllString(lower, -1) {
		if stop[m] {
			continue
		}
		out = append(out, m)
	}
	return out
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func textOf(e dynamic.Entry) string {
	return strings.Join([]string{e.CVE, e.Title, e.Description, e.Service, e.Version, strings.Join(e.References, " ")}, " ")
}

func dot(a, b []float64) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	s := 0.0
	for i := 0; i < n; i++ {
		s += a[i] * b[i]
	}
	return s
}

func l2(a []float64) float64 {
	s := 0.0
	for _, x := range a {
		s += x * x
	}
	return math.Sqrt(s)
}
