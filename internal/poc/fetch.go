package poc

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const exploitDBRawURL = "https://www.exploit-db.com/raw/%s"
const exploitDBGitURL = "https://raw.githubusercontent.com/offsecng/exploitdb/main/%s"
const userAgent = "apophis-poc-executor/0.1"

type Fetcher struct {
	Client *http.Client
}

func NewFetcher() *Fetcher {
	return &Fetcher{Client: &http.Client{Timeout: 30 * time.Second}}
}

func (f *Fetcher) get(ctx context.Context, url string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := f.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return "", fmt.Errorf("HTTP %d for %s", resp.StatusCode, url)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// FetchByEDB pulls a PoC by its Exploit-DB id. Tries the public raw mirror
// first, falls back to the GitHub mirror if the path is supplied.
func (f *Fetcher) FetchByEDB(ctx context.Context, id, filePath string) (string, PoCType, error) {
	if raw, err := f.get(ctx, fmt.Sprintf(exploitDBRawURL, id)); err == nil && strings.TrimSpace(raw) != "" {
		return raw, sniffType(raw, filePath), nil
	}
	if filePath != "" {
		raw, err := f.get(ctx, fmt.Sprintf(exploitDBGitURL, filePath))
		if err != nil {
			return "", "", err
		}
		return raw, sniffType(raw, filePath), nil
	}
	return "", "", fmt.Errorf("exploitdb id %s not retrievable", id)
}

func sniffType(raw, filePath string) PoCType {
	low := strings.ToLower(filePath)
	switch {
	case strings.HasSuffix(low, ".py"):
		return PoCTypePython
	case strings.HasSuffix(low, ".rb"):
		return PoCTypeRuby
	case strings.HasSuffix(low, ".js"):
		return PoCTypeJS
	case strings.HasSuffix(low, ".sh"):
		return PoCTypeShell
	case strings.HasSuffix(low, ".txt") || strings.HasSuffix(low, ".md"):
		if isPython(raw) {
			return PoCTypePython
		}
		if isRuby(raw) {
			return PoCTypeRuby
		}
		if isShell(raw) {
			return PoCTypeShell
		}
	}
	if isPython(raw) {
		return PoCTypePython
	}
	if isRuby(raw) {
		return PoCTypeRuby
	}
	if isShell(raw) {
		return PoCTypeShell
	}
	return PoCTypeOther
}

func isPython(s string) bool {
	first := firstNonEmpty(s)
	return strings.HasPrefix(first, "#!/usr/bin/env python") ||
		strings.HasPrefix(first, "#!/usr/bin/python") ||
		strings.Contains(s, "import os") && strings.Contains(s, "print(")
}

func isRuby(s string) bool {
	first := firstNonEmpty(s)
	return strings.HasPrefix(first, "#!/usr/bin/env ruby") ||
		strings.HasPrefix(first, "#!/usr/bin/ruby") ||
		strings.Contains(s, "require '")
}

func isShell(s string) bool {
	first := firstNonEmpty(s)
	return strings.HasPrefix(first, "#!/bin/sh") ||
		strings.HasPrefix(first, "#!/bin/bash") ||
		strings.HasPrefix(first, "#!/usr/bin/env bash")
}

func firstNonEmpty(s string) string {
	for _, line := range strings.SplitN(s, "\n", 10) {
		t := strings.TrimSpace(line)
		if t != "" {
			return t
		}
	}
	return ""
}

func (f *Fetcher) RequiresNet(s string) bool {
	low := strings.ToLower(s)
	keys := []string{"connect", "socket", "http://", "https://", "tcp", "udp", "requests.", "urlopen", "dial"}
	for _, k := range keys {
		if strings.Contains(low, k) {
			return true
		}
	}
	return false
}
