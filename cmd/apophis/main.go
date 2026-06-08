package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/apophis-eng/apophis/internal/logger"
	apomcp "github.com/apophis-eng/apophis/internal/mcp"
	"github.com/apophis-eng/apophis/internal/poc"
	"github.com/apophis-eng/apophis/internal/research"
	"github.com/apophis-eng/apophis/internal/store"
	"github.com/apophis-eng/apophis/internal/tools/cve/dynamic"
)

const usage = `
apophis — vulnerability chaos engine (MCP server for OpenCode)

usage:
  apophis [options]

options:
  -store                   directory to persist reports (default ~/.apophis/reports)
  -workers                 default parallel agents for audits (default 6)
  -timeout                 default per-probe timeout (default 5s)
  -h                       show this help

  PoC executor (off by default, requires explicit opt-in):
  -enable-executor         turn on the PoC executor
  -max-risk                info|safe|rce|destructive (default rce)
  -allow-container-sandbox enable L2 (runc/container) sandbox
  -executor-user           uid the PoC subprocess should drop to
  -execution-timeout       hard kill timeout for a PoC (default 5m)
  -allow-targets           path to allowlist file (default ~/.apophis/allowlist.txt)
  -no-allowlist            start without an allowlist (warning printed)
  -dry-run-executor        every PoC run is a stub (exit 0, no execution)
  -msfrpc-url              metasploit msfrpcd URL (e.g. http://127.0.0.1:55553)
  -msfrpc-user             msfrpcd username (default msf)
  -msfrpc-pass             msfrpcd password
  -nuclei-binary           path to nuclei (default: nuclei in PATH)
  -nuclei-templates        path to nuclei templates directory
  -boofuzz-python          python3 binary for boofuzz (default: python3)

When run, the server speaks MCP over stdio and exposes the following tools
to the host AI client:

  apophis_audit                  full multi-strategy parallel scan
  apophis_portscan               quick TCP port + banner scan
  apophis_web_audit              focused web application audit
  apophis_check_cve              match service/version against CVE db
  apophis_list_reports           list stored reports
  apophis_get_report             retrieve a stored report
  apophis_delete_report          delete a report
  apophis_recommend_exploitation exploit guides for findings
  apophis_research               sync latest CVEs from public sources
  apophis_search_cve             search the dynamic CVE database
  apophis_recent_cves            show the latest CVEs by CVSS/date
  apophis_generate_stub         generate a Go check stub for a CVE
  apophis_poc_list               list PoCs in the local store
  apophis_poc_preview            preview a PoC run without executing
  apophis_poc_run                execute a PoC (requires confirm:true)
  apophis_poc_history            list past PoC executions
  apophis_poc_kill               kill a running PoC execution
  apophis_poc_allowlist          manage the allowlist of allowed targets
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

		enableExec     = flag.Bool("enable-executor", false, "enable PoC executor (off by default)")
		maxRisk        = flag.String("max-risk", "rce", "max risk level: info|safe|rce|destructive")
		allowContainer = flag.Bool("allow-container-sandbox", false, "allow L2 container sandbox (opt-in)")
		executorUser   = flag.String("executor-user", "apophis-exec", "user to run PoCs as")
		execTimeout    = flag.Duration("execution-timeout", 5*time.Minute, "max PoC execution time")
		allowTargets   = flag.String("allow-targets", defaultAllowlist(), "path to target allowlist")
		noAllowlist    = flag.Bool("no-allowlist", false, "start without an allowlist (warning)")
		dryRun         = flag.Bool("dry-run-executor", false, "stub all PoC runs (no real execution)")

		msfrpcURL    = flag.String("msfrpc-url", "", "metasploit msfrpcd URL (e.g. http://127.0.0.1:55553)")
		msfrpcUser   = flag.String("msfrpc-user", "msf", "msfrpcd username")
		msfrpcPass   = flag.String("msfrpc-pass", "", "msfrpcd password")
		nucleiBin    = flag.String("nuclei-binary", "nuclei", "path to nuclei binary")
		nucleiTpl    = flag.String("nuclei-templates", "", "path to nuclei templates directory")
		boofuzzPy    = flag.String("boofuzz-python", "python3", "python3 binary for boofuzz")
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

	execCfg, execState := buildExecutor(*enableExec, *maxRisk, *allowContainer, *executorUser, *execTimeout, *allowTargets, *noAllowlist, *dryRun, abs, *msfrpcURL, *msfrpcUser, *msfrpcPass, *nucleiBin, *nucleiTpl, *boofuzzPy)

	if execCfg.Enabled && execState != nil && !execState.AllowlistOK && !*noAllowlist {
		fmt.Fprintf(os.Stderr, "apophis: allowlist not found at %s (use -no-allowlist to bypass, or create the file)\n", execState.AllowlistPath)
		os.Exit(2)
	}
	if execCfg.Enabled {
		logger.Warn("apophis", fmt.Sprintf("PoC executor ENABLED max-risk=%s allow-container=%v executor-user=%s timeout=%s dry-run=%v", execCfg.MaxRisk, execCfg.AllowContainer, execCfg.ExecutorUser, execCfg.ExecutionTimeout, execCfg.DryRun))
	} else {
		logger.Info("apophis", "PoC executor disabled (start with -enable-executor to turn on)")
	}

	srv := mcp.NewServer(&mcp.Implementation{
		Name:    "apophis",
		Version: "0.2.0",
	}, &mcp.ServerOptions{
		Instructions: "Apophis is a vulnerability chaos engine with an integrated vulnerability research agent. Use apophis_audit for a full multi-strategy scan, apophis_check_cve / apophis_recent_cves / apophis_search_cve to look up CVEs, and apophis_research to sync the latest vulnerabilities from NVD/OSV/CISA-KEV/GHSA/Exploit-DB/security RSS feeds. Only run against systems you own or are authorized to test.",
	})

	apomcp.NewServer(st, dyn, agent, execState, *workers, *timeout).Register(srv)

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

func defaultAllowlist() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".apophis/allowlist.txt"
	}
	return filepath.Join(home, ".apophis", "allowlist.txt")
}

func buildExecutor(enable bool, maxRisk string, allowContainer bool, execUser string, execTimeout time.Duration, allowTargets string, noAllowlist, dryRun bool, storeDir, msfrpcURL, msfrpcUser, msfrpcPass, nucleiBin, nucleiTpl, boofuzzPy string) (poc.ExecConfig, *poc.State) {
	cfg := poc.ExecConfig{
		Enabled:          enable,
		MaxRisk:          poc.ParseRisk(maxRisk),
		AllowContainer:   allowContainer,
		ExecutorUser:     execUser,
		ExecutionTimeout: execTimeout,
		AllowlistPath:    allowTargets,
		NoAllowlist:      noAllowlist,
		DryRun:           dryRun,
		AuditDir:         filepath.Join(storeDir, "executions"),
		SecretKeyPath:    filepath.Join(storeDir, "exec-secret.key"),
		WorkDir:          filepath.Join(os.TempDir(), "apophis-poc"),
		MaxSandboxLevel:  poc.SandboxL1,
		MSFRPCURL:        msfrpcURL,
		MSFRPCUser:       msfrpcUser,
		MSFRPCPass:       msfrpcPass,
		NucleiBinary:     nucleiBin,
		NucleiTemplatesDir: nucleiTpl,
		BoofuzzPython:    boofuzzPy,
	}
	if cfg.AllowContainer {
		cfg.MaxSandboxLevel = poc.SandboxL2
	}
	if cfg.MaxRisk < 0 {
		cfg.MaxRisk = poc.RiskRCE
	}
	if !enable {
		return cfg, nil
	}
	if u, err := user.Lookup(execUser); err == nil {
		_ = u
	} else {
		logger.Warn("apophis", fmt.Sprintf("executor-user %q not found; will run as current user (privilege separation degraded)", execUser))
	}
	var allow *poc.Allowlist
	allowOK := false
	if !noAllowlist {
		al, err := poc.LoadAllowlistFile(allowTargets)
		if err == nil {
			allow = al
			allowOK = al.Len() > 0
		}
	}
	if allow == nil {
		allow = poc.NewAllowlist()
	}
	audit, err := poc.OpenAuditLog(cfg.AuditDir, cfg.SecretKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "apophis: cannot init audit log: %v\n", err)
		os.Exit(1)
	}
	pocStore, err := poc.OpenStore(filepath.Join(storeDir, "pocs"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "apophis: cannot init PoC store: %v\n", err)
		os.Exit(1)
	}
	state := poc.NewState(cfg, allow, audit, pocStore)
	state.AllowlistPath = allowTargets
	state.AllowlistOK = allowOK
	return cfg, state
}
