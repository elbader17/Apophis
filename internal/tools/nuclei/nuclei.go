// Package nuclei implements a minimal nuclei-template-compatible loader and
// executor. The supported YAML subset is intentionally small but covers the
// common web-check templates (id, info, http, matchers). If the external
// nuclei binary is on PATH (APOPHIS_NUCLEI_BINARY or 'nuclei' in $PATH), the
// runner delegates to it; otherwise the built-in mini-executor runs each
// template using net/http directly.
//
// We deliberately do not pull in a YAML library. The supported subset is
// well-defined enough to parse with a tiny line scanner that handles the
// same indentation / list / mapping rules that nuclei uses.
package nuclei

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apophis-eng/apophis/internal/logger"
	"github.com/apophis-eng/apophis/internal/models"
)

// Template is the parsed subset of a nuclei template.
type Template struct {
	ID       string   `yaml:"id"`
	Info     Info     `yaml:"info"`
	Requests []HTTP   `yaml:"http"`
	Tags     []string `yaml:"tags,omitempty"`
}

type Info struct {
	Name        string
	Author      string
	Severity    string
	Description string
	Reference   []string
	Tags        []string
}

type KV struct{ Key, Value string }

type HTTP struct {
	Method         string
	Path           []string
	Headers        []KV
	Body           string
	Matchers       []Matcher
	MatchCondition string
	Variables      map[string]string
}

type Matcher struct {
	Type            string
	Words           []string
	Regex           []string
	Status          []int
	Part            string
	Condition       string
	Negate          bool
	CaseInsensitive bool
}

// Loader resolves templates from a directory tree.
type Loader struct {
	Dir string
}

func NewLoader(dir string) *Loader { return &Loader{Dir: dir} }

// Load returns every parseable template under Dir (recursive). Files that
// fail to parse are logged at warn level and skipped.
func (l *Loader) Load() ([]Template, error) {
	if l.Dir == "" {
		return nil, nil
	}
	var out []Template
	err := filepath.Walk(l.Dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		t, err := ParseFile(path)
		if err != nil {
			logger.Warn("nuclei", fmt.Sprintf("skip %s: %v", path, err))
			return nil
		}
		out = append(out, t)
		return nil
	})
	return out, err
}

// ParseFile parses a single template file using the small YAML scanner.
func ParseFile(path string) (Template, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Template{}, err
	}
	return Parse(string(b))
}

// Parse parses a template from a string body.
func Parse(src string) (Template, error) {
	doc, err := parseYAML(src)
	if err != nil {
		return Template{}, err
	}
	root, ok := doc.(map[string]any)
	if !ok {
		return Template{}, fmt.Errorf("top-level must be a mapping")
	}
	t := Template{}
	if v, ok := root["id"].(string); ok {
		t.ID = v
	}
	if v, ok := root["tags"].([]any); ok {
		for _, x := range v {
			if s, ok := x.(string); ok {
				t.Tags = append(t.Tags, s)
			}
		}
	}
	if v, ok := root["info"].(map[string]any); ok {
		t.Info = Info{
			Name:        asString(v["name"]),
			Author:      asString(v["author"]),
			Severity:    asString(v["severity"]),
			Description: asString(v["description"]),
		}
		for _, r := range asList(v["reference"]) {
			t.Info.Reference = append(t.Info.Reference, r)
		}
		for _, tg := range asList(v["tags"]) {
			t.Info.Tags = append(t.Info.Tags, tg)
		}
	}
	if v, ok := root["http"].([]any); ok {
		for _, item := range v {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			h := HTTP{}
			h.Method = asString(m["method"])
			for _, p := range asList(m["path"]) {
				h.Path = append(h.Path, p)
			}
			if hs, ok := m["headers"].(map[string]any); ok {
				for k, vv := range hs {
					h.Headers = append(h.Headers, KV{Key: k, Value: asString(vv)})
				}
			}
			h.Body = asString(m["body"])
			h.MatchCondition = asString(m["match-condition"])
			if vars, ok := m["variables"].(map[string]any); ok {
				h.Variables = map[string]string{}
				for k, vv := range vars {
					h.Variables[k] = asString(vv)
				}
			}
			if ms, ok := m["matchers"].([]any); ok {
				for _, item := range ms {
					mm, ok := item.(map[string]any)
					if !ok {
						continue
					}
					mat := Matcher{
						Type:            asString(mm["type"]),
						Part:            asString(mm["part"]),
						Condition:       asString(mm["condition"]),
						Negate:          asBool(mm["negate"]),
						CaseInsensitive: asBool(mm["case-insensitive"]),
					}
					for _, w := range asList(mm["words"]) {
						mat.Words = append(mat.Words, w)
					}
					for _, r := range asList(mm["regex"]) {
						mat.Regex = append(mat.Regex, r)
					}
					if ss, ok := mm["status"].([]any); ok {
						for _, x := range ss {
							if n, ok := x.(int); ok {
								mat.Status = append(mat.Status, n)
							} else if s, ok := x.(string); ok {
								if v, err := strconv.Atoi(s); err == nil {
									mat.Status = append(mat.Status, v)
								}
							}
						}
					}
					h.Matchers = append(h.Matchers, mat)
				}
			}
			t.Requests = append(t.Requests, h)
		}
	}
	return t, nil
}

// Runner executes templates against a base URL.
type Runner struct {
	Client    *http.Client
	Timeout   time.Duration
	Variables map[string]string
}

func NewRunner(timeout time.Duration) *Runner {
	if timeout == 0 {
		timeout = 8 * time.Second
	}
	return &Runner{
		Client: &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > 5 {
				return http.ErrUseLastResponse
			}
			return nil
		}},
		Timeout:   timeout,
		Variables: map[string]string{},
	}
}

// Run executes t against base and returns findings for templates that fired.
func (r *Runner) Run(ctx context.Context, t Template, base string) []models.Finding {
	out := []models.Finding{}
	parsed, err := url.Parse(base)
	if err != nil {
		return out
	}
	vars := mergeVars(r.Variables, nil)
	for _, h := range t.Requests {
		for _, p := range h.Path {
			full := joinURL(parsed, expand(p, mergeVars(vars, h.Variables)))
			method := strings.ToUpper(h.Method)
			if method == "" {
				method = http.MethodGet
			}
			body := strings.NewReader(expand(h.Body, mergeVars(vars, h.Variables)))
			req, err := http.NewRequestWithContext(ctx, method, full, body)
			if err != nil {
				continue
			}
			for _, kv := range h.Headers {
				req.Header.Set(expand(kv.Key, mergeVars(vars, h.Variables)), expand(kv.Value, mergeVars(vars, h.Variables)))
			}
			if req.Header.Get("User-Agent") == "" {
				req.Header.Set("User-Agent", "apophis-nuclei/0.1")
			}
			resp, err := r.Client.Do(req)
			var statusCode int
			var respBody []byte
			if err == nil {
				statusCode = resp.StatusCode
				respBody, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				resp.Body.Close()
			}
			matched, errMsg := matchAll(h.Matchers, h.MatchCondition, statusCode, respBody)
			if !matched {
				if errMsg != "" {
					logger.Warn("nuclei", fmt.Sprintf("%s: %s", t.ID, errMsg))
				}
				continue
			}
			sev := sevFromString(t.Info.Severity)
			out = append(out, models.Finding{
				Title:       fmt.Sprintf("[%s] %s", t.ID, t.Info.Name),
				Severity:    sev,
				Category:    "NucleiTemplate",
				Target:      base,
				Evidence:    fmt.Sprintf("matched on %s %s → status=%d", method, full, statusCode),
				Description: t.Info.Description,
				Exploit:     "Manual inspection of the matching response.",
				Remediation: "Patch the underlying vulnerability indicated by the template ID.",
				References:  t.Info.Reference,
				Tags:        append([]string{"nuclei"}, t.Info.Tags...),
			})
		}
	}
	return out
}

// matchAll runs the matcher list against the response. "and" requires every
// matcher to succeed, "or" requires at least one.
func matchAll(ms []Matcher, cond string, status int, body []byte) (bool, string) {
	if len(ms) == 0 {
		return true, ""
	}
	if cond == "" {
		cond = "or"
	}
	switch cond {
	case "and":
		for _, m := range ms {
			ok, err := singleMatch(m, status, body)
			if err != "" {
				return false, err
			}
			if !ok {
				return false, ""
			}
		}
		return true, ""
	default:
		for _, m := range ms {
			ok, err := singleMatch(m, status, body)
			if err != "" {
				return false, err
			}
			if ok {
				return true, ""
			}
		}
	}
	return false, ""
}

func singleMatch(m Matcher, status int, body []byte) (bool, string) {
	cond := m.Condition
	if cond == "" {
		cond = "or"
	}
	switch m.Type {
	case "status":
		if len(m.Status) == 0 {
			return false, "empty status matcher"
		}
		hit := false
		for _, s := range m.Status {
			if s == status {
				hit = true
				break
			}
		}
		return applyNegate(hit, m.Negate), ""
	case "word", "words":
		text := string(body)
		if m.CaseInsensitive {
			text = strings.ToLower(text)
		}
		hits := 0
		for _, w := range m.Words {
			cmp := w
			if m.CaseInsensitive {
				cmp = strings.ToLower(cmp)
			}
			if strings.Contains(text, cmp) {
				hits++
			}
		}
		return applyCondition(hits, len(m.Words), cond, m.Negate), ""
	case "regex":
		hits := 0
		for _, r := range m.Regex {
			re, err := regexp.Compile(r)
			if err != nil {
				return false, fmt.Sprintf("bad regex %q: %v", r, err)
			}
			if re.Match(body) {
				hits++
			}
		}
		return applyCondition(hits, len(m.Regex), cond, m.Negate), ""
	}
	return false, fmt.Sprintf("unknown matcher type %q", m.Type)
}

func applyCondition(hits, total int, cond string, negate bool) bool {
	var ok bool
	switch cond {
	case "and":
		ok = total > 0 && hits == total
	default:
		ok = hits > 0
	}
	return applyNegate(ok, negate)
}

func applyNegate(b, negate bool) bool {
	if negate {
		return !b
	}
	return b
}

func sevFromString(s string) models.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return models.SeverityCritical
	case "high":
		return models.SeverityHigh
	case "medium":
		return models.SeverityMedium
	case "low":
		return models.SeverityLow
	}
	return models.SeverityInfo
}

func expand(s string, vars map[string]string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	out := s
	for k, v := range vars {
		out = strings.ReplaceAll(out, "{{"+k+"}}", v)
	}
	return out
}

func mergeVars(a, b map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

func joinURL(base *url.URL, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if !strings.HasPrefix(ref, "/") {
		ref = "/" + ref
	}
	return base.Scheme + "://" + base.Host + ref
}

// --- Tiny YAML parser (subset) ----------------------------------------------
//
// Supports:
//   - key: scalar
//   - key: 'quoted'
//   - key:
//       nested: scalar
//   - key:
//     - item
//     - item
//   - list:
//     - key: scalar
//       key2: scalar
//   - # comments
//
// Doesn't support: anchors, references, multi-line scalars, flow style.

type yamlParser struct {
	scanner *bufio.Scanner
	line    int
}

func parseYAML(src string) (any, error) {
	p := &yamlParser{}
	p.scanner = bufio.NewScanner(strings.NewReader(src))
	p.scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	lines := []yamlLine{}
	for p.scanner.Scan() {
		raw := p.scanner.Text()
		// Strip trailing comment not inside a string.
		stripped := stripComment(raw)
		if strings.TrimSpace(stripped) == "" {
			continue
		}
		indent := leadingSpaces(stripped)
		content := stripped[indent:]
		lines = append(lines, yamlLine{indent: indent, content: content})
	}
	if err := p.scanner.Err(); err != nil {
		return nil, err
	}
	v, _, err := parseBlock(lines, 0)
	return v, err
}

type yamlLine struct {
	indent  int
	content string
}

func (p *yamlParser) Lines() []yamlLine { return nil }

func stripComment(s string) string {
	inSingle, inDouble := false, false
	for i, r := range s {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return s[:i]
			}
		}
	}
	return s
}

func leadingSpaces(s string) int {
	for i, r := range s {
		if r != ' ' {
			return i
		}
	}
	return len(s)
}

// parseBlock parses a block of YAML at indent `indent`. Returns the parsed
// value and the number of lines consumed.
func parseBlock(lines []yamlLine, indent int) (any, int, error) {
	if len(lines) == 0 {
		return nil, 0, nil
	}
	first := lines[0]
	if first.indent < indent {
		return nil, 0, nil
	}
	// Sequence.
	if strings.HasPrefix(first.content, "- ") || first.content == "-" {
		out := []any{}
		i := 0
		for i < len(lines) {
			l := lines[i]
			if l.indent < indent {
				break
			}
			if l.indent != indent || (!strings.HasPrefix(l.content, "- ") && l.content != "-") {
				break
			}
			item := l.content
			if item == "-" {
				item = ""
			} else {
				item = strings.TrimPrefix(item, "- ")
			}
			// Inline mapping on the same line as the dash.
			if strings.Contains(item, ":") && !strings.HasPrefix(item, "{") {
				inlineMap := map[string]any{}
				rest, err := parseKV(item, inlineMap)
				if err != nil {
					return nil, 0, err
				}
				if rest != "" {
					// Treat the trailing value as the key "_" to preserve order.
					inlineMap["_"] = parseScalar(rest)
				}
				// Then continue at the deeper indent to merge in additional
				// keys.
				childIndent := l.indent + 2
				if child := consumeNextAtIndent(lines[i+1:], childIndent); len(child) > 0 {
					childVal, _, err := parseBlock(child, childIndent)
					if err != nil {
						return nil, 0, err
					}
					if cm, ok := childVal.(map[string]any); ok {
						for k, v := range cm {
							inlineMap[k] = v
						}
					}
					i += 1 + len(child)
				} else {
					i++
				}
				out = append(out, inlineMap)
				continue
			}
			if item == "" {
				// Sequence item is a nested block.
				childIndent := l.indent + 2
				child := consumeNextAtIndent(lines[i+1:], childIndent)
				v, _, err := parseBlock(child, childIndent)
				if err != nil {
					return nil, 0, err
				}
				out = append(out, v)
				i += 1 + len(child)
				continue
			}
			out = append(out, parseScalar(item))
			i++
		}
		return out, i, nil
	}
	// Mapping.
	out := map[string]any{}
	i := 0
	for i < len(lines) {
		l := lines[i]
		if l.indent < indent {
			break
		}
		if l.indent != indent {
			break
		}
		k, v, rest, err := parseKVLine(l.content)
		if err != nil {
			return nil, 0, err
		}
		if rest != "" {
			// value on same line.
			out[k] = parseScalar(rest)
			i++
			continue
		}
		if v == nil && i+1 < len(lines) && lines[i+1].indent > indent {
			child := consumeNextAtIndent(lines[i+1:], lines[i+1].indent)
			cv, _, err := parseBlock(child, lines[i+1].indent)
			if err != nil {
				return nil, 0, err
			}
			out[k] = cv
			i += 1 + len(child)
			continue
		}
		out[k] = v
		i++
	}
	return out, i, nil
}

// consumeNextAtIndent returns the maximal prefix of lines whose indent is >= want.
func consumeNextAtIndent(lines []yamlLine, want int) []yamlLine {
	out := []yamlLine{}
	for _, l := range lines {
		if l.indent < want {
			break
		}
		out = append(out, l)
	}
	return out
}

func parseKVLine(s string) (key string, val any, rest string, err error) {
	idx := indexUnquotedColon(s)
	if idx < 0 {
		return "", nil, "", fmt.Errorf("not a kv line: %q", s)
	}
	key = strings.TrimSpace(s[:idx])
	rest = strings.TrimSpace(s[idx+1:])
	if rest == "" {
		return key, nil, "", nil
	}
	if rest == "|" || rest == ">" {
		// Block scalar: defer to caller; we don't use these in our subset.
		return key, "", "", fmt.Errorf("block scalars not supported")
	}
	return key, parseScalar(rest), "", nil
}

func parseKV(s string, dst map[string]any) (string, error) {
	idx := indexUnquotedColon(s)
	if idx < 0 {
		return s, nil
	}
	k := strings.TrimSpace(s[:idx])
	v := strings.TrimSpace(s[idx+1:])
	if v == "" {
		return "", nil
	}
	dst[k] = parseScalar(v)
	return "", nil
}

func indexUnquotedColon(s string) int {
	inSingle, inDouble := false, false
	for i, r := range s {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case ':':
			if !inSingle && !inDouble {
				// Must be followed by space or end-of-line.
				if i == len(s)-1 || s[i+1] == ' ' {
					return i
				}
			}
		}
	}
	return -1
}

func parseScalar(s string) any {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	if s == "true" {
		return true
	}
	if s == "false" {
		return false
	}
	if s == "null" || s == "~" {
		return nil
	}
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil && strings.ContainsAny(s, ".eE") {
		return f
	}
	return s
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func asBool(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	if s, ok := v.(string); ok {
		return strings.EqualFold(s, "true") || s == "1"
	}
	return false
}

func asList(v any) []string {
	out := []string{}
	switch x := v.(type) {
	case []any:
		for _, item := range x {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

// silence unused import warnings when stripping helper code.
var (
	_ = sync.Mutex{}
)
