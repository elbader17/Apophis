package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {
	bin := os.Getenv("APOPHIS_BIN")
	if bin == "" {
		bin = "./bin/apophis"
	}

	storeDir := "/tmp/apophis-test-store"
	os.RemoveAll(storeDir)
	os.MkdirAll(storeDir, 0755)

	cmd := exec.Command(bin, "-store", storeDir, "-workers", "3", "-timeout", "2s")
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "APOPHIS_NO_BANNER=1")

	transport := &mcp.CommandTransport{Command: cmd}
	client := mcp.NewClient(&mcp.Implementation{Name: "tester", Version: "0.1"}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sess, err := client.Connect(ctx, transport, nil)
	if err != nil {
		fmt.Println("connect:", err)
		os.Exit(1)
	}
	defer func() {
		sess.Close()
		if cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()

	tools, err := sess.ListTools(ctx, nil)
	if err != nil {
		fmt.Println("list tools:", err)
		os.Exit(1)
	}
	fmt.Println("== TOOLS ==")
	for _, t := range tools.Tools {
		fmt.Printf("  - %s: %s\n", t.Name, truncate(t.Description, 80))
	}

	fmt.Println("\n== apophis_status ==")
	out, _ := call(ctx, sess, "apophis_status", map[string]any{})
	fmt.Println(out)

	fmt.Println("\n== apophis_check_cve (log4j) ==")
	out, _ = call(ctx, sess, "apophis_check_cve", map[string]any{
		"service": "log4j",
		"version": "2.14.0",
		"banner":  "log4j 2.14.0",
	})
	fmt.Println(truncate(out, 1500))

	fmt.Println("\n== apophis_check_cve (ssh OpenSSH 6.6.1) ==")
	out, _ = call(ctx, sess, "apophis_check_cve", map[string]any{
		"service": "ssh",
		"version": "OpenSSH_6.6.1p1",
		"banner":  "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13",
	})
	fmt.Println(truncate(out, 1500))

	fmt.Println("\n== apophis_check_cve (smb wildcard) ==")
	out, _ = call(ctx, sess, "apophis_check_cve", map[string]any{
		"service": "smb",
		"version": "",
		"banner":  "",
	})
	fmt.Println(truncate(out, 2000))

	fmt.Println("\n== apophis_list_reports (empty) ==")
	out, _ = call(ctx, sess, "apophis_list_reports", map[string]any{"limit": 5})
	fmt.Println(out)

	fmt.Println("\n== apophis_audit (assume test target on 9993) ==")
	out, _ = call(ctx, sess, "apophis_audit", map[string]any{
		"target":  "127.0.0.1",
		"url":     "http://127.0.0.1:9993",
		"workers": 3,
		"timeout": "3s",
		"ports":   "9993",
	})
	fmt.Println(out)

	fmt.Println("\n== apophis_list_reports (after audit) ==")
	out, _ = call(ctx, sess, "apophis_list_reports", map[string]any{"limit": 5})
	fmt.Println(out)

	fmt.Println("\n== apophis_recommend_exploitation ==")
	out, _ = call(ctx, sess, "apophis_recommend_exploitation", map[string]any{
		"severity":    "CRITICAL",
		"max_results": 3,
	})
	fmt.Println(truncate(out, 2500))

	fmt.Println("\n== apophis_status (with research) ==")
	out, _ = call(ctx, sess, "apophis_status", map[string]any{})
	fmt.Println(out)

	fmt.Println("\n== apophis_research (CISA-KEV only, 10 entries) ==")
	out, _ = call(ctx, sess, "apophis_research", map[string]any{
		"sources":        []string{"cisa-kev"},
		"days_back":      3650,
		"max_per_source": 10,
	})
	fmt.Println(truncate(out, 2500))

	fmt.Println("\n== apophis_search_cve (keyword=Windows) ==")
	out, _ = call(ctx, sess, "apophis_search_cve", map[string]any{
		"keyword": "Windows",
		"limit":   5,
	})
	fmt.Println(truncate(out, 2500))

	fmt.Println("\n== apophis_recent_cves (KEV only) ==")
	out, _ = call(ctx, sess, "apophis_recent_cves", map[string]any{
		"only_kev": true,
		"limit":    5,
	})
	fmt.Println(truncate(out, 2000))

	fmt.Println("\n== apophis_check_cve (log4j with dynamic store) ==")
	out, _ = call(ctx, sess, "apophis_check_cve", map[string]any{
		"service": "log4j",
		"version": "2.14.0",
	})
	fmt.Println(truncate(out, 1500))
}

func call(ctx context.Context, sess *mcp.ClientSession, name string, args map[string]any) (string, error) {
	res, err := sess.CallTool(ctx, &mcp.CallToolParams{
		Name:      name,
		Arguments: args,
	})
	if err != nil {
		return "", err
	}
	if res.IsError {
		return "ERROR: " + fmt.Sprint(res.Content), nil
	}
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			return tc.Text, nil
		}
	}
	b, _ := json.MarshalIndent(res, "", "  ")
	return string(b), nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "...[truncated]"
}
