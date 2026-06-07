package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/apophis-eng/apophis/internal/logger"
	apomcp "github.com/apophis-eng/apophis/internal/mcp"
	"github.com/apophis-eng/apophis/internal/research"
	"github.com/apophis-eng/apophis/internal/store"
	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
)

const usage = `
apophis — vulnerability chaos engine (MCP server for OpenCode)

usage:
  apophis [options]

options:
  -store       directory to persist reports (default ~/.apophis/reports)
  -workers     default parallel agents for audits (default 6)
  -timeout     default per-probe timeout (default 5s)
  -h           show this help

When run, the server speaks MCP over stdio and exposes the following tools
to the host AI client:

  apophis_audit                  full multi-strategy parallel scan
  apophis_portscan               quick TCP port + banner scan
  apophis_web_audit              focused web application audit
  apophis_check_cve              match service/version against CVE db
  apophis_list_reports           list stored reports
  apophis_get_report             retrieve a stored report
  apophis_delete_report          delete a stored report
  apophis_recommend_exploitation exploit guides for findings
  apophis_research               sync latest CVEs from public sources
  apophis_search_cve             search the dynamic CVE database
  apophis_recent_cves            show the latest CVEs by CVSS/date
  apophis_generate_stub         generate a Go check stub for a CVE
  apophis_status                 server status

Environment variables (override flags):
  APOPHIS_WORKERS   default parallel agents
  APOPHIS_TIMEOUT   default per-probe timeout (Go duration syntax)
  APOPHIS_STORE     store directory
  APOPHIS_NVD_KEY   NVD API key (faster rate, get from https://nvd.nist.gov/)
  APOPHIS_GH_TOKEN  GitHub personal access token (for higher GraphQL rate)

⚠ Use only against systems you own or are authorized to test.
`

func main() {
	var (
		storeDir = flag.String("store", defaultStore(), "directory to persist reports")
		workers  = flag.Int("workers", 6, "default parallel agents")
		timeout  = flag.Duration("timeout", 5*time.Second, "default per-probe timeout")
		showHelp = flag.Bool("h", false, "show help")
	)
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if *showHelp {
		fmt.Print(usage)
		return
	}

	if os.Getenv("APOPHIS_NO_BANNER") == "" {
		logger.Banner()
	}

	if v := os.Getenv("APOPHIS_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*workers = n
		}
	}
	if v := os.Getenv("APOPHIS_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			*timeout = d
		}
	}
	if v := os.Getenv("APOPHIS_STORE"); v != "" {
		*storeDir = v
	}

	abs, _ := filepath.Abs(*storeDir)
	st, err := store.New(abs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apophis: cannot init store at %s: %v\n", abs, err)
		os.Exit(1)
	}
	logger.Info("apophis", "store at "+abs)

	dyn, err := dynamic.Open(abs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apophis: cannot init dynamic cve store: %v\n", err)
		os.Exit(1)
	}
	logger.Info("apophis", fmt.Sprintf("dynamic CVE store: %s (%d entries)", dyn.Path(), dyn.Len()))

	nvdKey := os.Getenv("APOPHIS_NVD_KEY")
	ghToken := os.Getenv("APOPHIS_GH_TOKEN")
	agent := research.New(dyn, nvdKey, ghToken)

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "apophis",
		Version: "0.2.0",
	}, &mcp.ServerOptions{
		Instructions: "Apophis is a vulnerability chaos engine with an integrated vulnerability research agent. Use apophis_audit for a full multi-strategy scan, apophis_check_cve / apophis_recent_cves / apophis_search_cve to look up CVEs, and apophis_research to sync the latest vulnerabilities from NVD/OSV/CISA-KEV/GHSA/Exploit-DB/security RSS feeds. Only run against systems you own or are authorized to test.",
	})

	apomcp.NewServer(st, dyn, agent, *workers, *timeout).Register(srv)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Warn("apophis", "shutdown signal received")
		cancel()
	}()

	logger.Info("apophis", fmt.Sprintf("stdio transport active — workers=%d timeout=%s", *workers, *timeout))

	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "apophis: stdio transport error: %v\n", err)
		os.Exit(1)
	}
}

func defaultStore() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".apophis/reports"
	}
	return filepath.Join(home, ".apophis", "reports")
}
