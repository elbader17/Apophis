package sources

import (
	"encoding/xml"
	"fmt"
	"strings"
	"time"

)

// RSSAdapter scrapes public security-blog RSS feeds. Each item in the feed
// is converted into a Finding. This complements the structured CVE sources
// with human-written context (e.g. "CVE-2024-xxxx actively exploited in the wild").
type RSSAdapter struct {
	SourceName string
	URL        string
	Extra      map[string]any
	Client     *Client
}

func (r *RSSAdapter) Name() string {
	if r.SourceName != "" {
		return r.SourceName
	}
	return "rss:" + r.URL
}

type rssFeed struct {
	XMLName xml.Name `xml:"rss"`
	Channel struct {
		Item []struct {
			Title       string `xml:"title"`
			Link        string `xml:"link"`
			Description string `xml:"description"`
			PubDate     string `xml:"pubDate"`
			GUID        string `xml:"guid"`
		} `xml:"item"`
	} `xml:"channel"`
}

func (r *RSSAdapter) Fetch(ctx SourceContext) ([]Finding, error) {
	c := r.Client
	if c == nil {
		c = NewClient("", "")
	}
	body, err := c.Get(ctxToCtx(ctx), r.URL)
	if err != nil {
		return nil, fmt.Errorf("rss %s: %w", r.Name(), err)
	}
	var f rssFeed
	if err := xml.Unmarshal(body, &f); err != nil {
		return nil, fmt.Errorf("rss %s decode: %w", r.Name(), err)
	}
	out := []Finding{}
	for _, item := range f.Channel.Item {
		pub, _ := parseRSSDate(item.PubDate)
		if !ctx.Since.IsZero() && !pub.IsZero() && pub.Before(ctx.Since) {
			continue
		}
		cve := extractCVE(item.Title + " " + item.Description)
		title := stripHTML(item.Title)
		f := Finding{
			Source:      r.Name(),
			CVE:         cve,
			Title:       title,
			Description: stripHTML(item.Description),
			Published:   pub,
			References:  []string{item.Link},
		}
		if f.Title == "" {
			continue
		}
		out = append(out, f)
		if ctx.MaxItems > 0 && len(out) >= ctx.MaxItems {
			break
		}
	}
	return out, nil
}

func parseRSSDate(s string) (time.Time, error) {
	for _, f := range []string{time.RFC1123Z, time.RFC1123, time.RFC822Z, time.RFC822, "2006-01-02T15:04:05Z"} {
		if t, err := time.Parse(f, strings.TrimSpace(s)); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("unparseable date: %q", s)
}

func stripHTML(s string) string {
	var b strings.Builder
	in := false
	for _, r := range s {
		switch {
		case r == '<':
			in = true
		case r == '>':
			in = false
		case !in:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

func extractCVE(s string) string {
	idx := strings.Index(s, "CVE-")
	if idx < 0 {
		return ""
	}
	end := idx + 4
	for end < len(s) {
		ch := s[end]
		if ch == '-' {
			end++
			continue
		}
		if ch >= '0' && ch <= '9' {
			end++
			continue
		}
		break
	}
	candidate := s[idx:end]
	for _, ch := range candidate {
		if !(ch == '-' || (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z')) {
			return candidate
		}
	}
	if len(candidate) < 9 {
		return ""
	}
	return candidate
}
