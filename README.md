# APOPHIS — Vulnerability Chaos Engine

> **Apophis** (Apep) is the Egyptian serpent-god of chaos, the eternal adversary of Ra who threatens to swallow the sun and unravel order. This engine channels that same relentless chaos against misconfigured, vulnerable, or exposed systems — and actively hunts for new weaknesses to break.

A **Model Context Protocol (MCP) server** for [OpenCode](https://github.com/sst/opencode) and any MCP-compatible AI client.

- **Parallel chaos agents** race against a target from different angles (recon, aggressive, stealth, web-focus, net-focus, auth-focus) and consolidate findings into structured reports
- **Integrated vulnerability research agent** that syncs CVEs and exploit PoCs from public sources (NVD, OSV, CISA KEV, GitHub Security Advisories, Exploit-DB, security RSS feeds) and updates the local database
- **Exploit tool generator** that produces ready-to-paste Go check stubs for new CVEs
- **Sandboxed PoC executor** with three isolation levels (Linux namespaces → runc container → Firecracker microVM), HMAC-signed audit log, persistent allow-list, and integrations for Metasploit (msfrpcd), nuclei, and boofuzz

```
 █████  ██████  ██   ██  █████  ██████  ██    ██ ██ ███████
██   ██ ██   ██ ██   ██ ██   ██ ██   ██ ██    ██ ██ ██
███████ ██████  ███████ ██   ██ ██████  ████████ ██ ███████ 
██   ██ ██      ██   ██ ██   ██ ██      ██    ██ ██      ██
██   ██ ██      ██   ██  █████  ██      ██    ██ ██ ███████
    vulnerability chaos engine
```

```
                          ┌────────────────────┐
                          │   MCP Host (LLM)   │
                          │   (OpenCode etc)   │
                          └──────────┬─────────┘
                                     │  JSON-RPC over stdio
                                     ▼
                          ┌────────────────────┐
                          │   APOPHIS server   │
                          │   (this binary)    │
                          └──────────┬─────────┘
                                     │
            ┌────────────────────────┼──────────────────────────┐
            │                        │                          │
            ▼                        ▼                          ▼
     ┌─────────────┐         ┌─────────────┐          ┌──────────────────┐
     │  scan ops   │         │  research   │          │  dynamic store   │
     │ chaos-N     │         │   agent     │          │  ~/.apophis/     │
     │ portscan    │         │  NVD/OSV/   │          │   dynamic-cves   │
     │ web/SSL/CVE │         │  KEV/GHSA/  │          │   .json          │
     │ auth        │         │  ExploitDB  │          └──────────────────┘
     └──────┬──────┘         │  /rss       │
            │                └──────┬──────┘
            │                       │
            └───────────┬───────────┘
                        ▼
            ┌──────────────────────┐
            │ ~/.apophis/reports/  │
            │  rpt-<id>.json+.md   │
            └──────────────────────┘
```

---

## Tools exposed

The server registers the following MCP tools, callable by the LLM:

### Attack & audit
| Tool | Purpose |
|------|---------|
| `apophis_audit` | Full multi-strategy parallel scan, returns report id + summary |
| `apophis_portscan` | Quick TCP port scan + banner grab |
| `apophis_web_audit` | Focused web app audit (headers, paths, LFI/SQLi/XSS, TLS) |
| `apophis_check_cve` | Match a service+version+banner against the **combined** static + dynamic CVE database |
| `apophis_recommend_exploitation` | Look up exploit guides for findings |
| `apophis_list_reports` | List all stored reports (filter by target substring) |
| `apophis_get_report` | Retrieve a stored report (summary / findings / json) |
| `apophis_delete_report` | Delete a report |

### Vulnerability research
| Tool | Purpose |
|------|---------|
| `apophis_research` | Sync the latest CVEs from NVD, OSV, CISA KEV, GitHub Security Advisories, Exploit-DB, security RSS feeds. Optionally generate Go check stubs. |
| `apophis_search_cve` | Search the dynamic CVE database by keyword / CVSS / severity / KEV-only |
| `apophis_recent_cves` | Show the most recent CVEs from the dynamic database |
| `apophis_generate_stub` | Generate a ready-to-paste Go check function for a specific CVE |

### Meta
| Tool | Purpose |
|------|---------|
| `apophis_status` | Server status & config |

### PoC executor (opt-in, off by default)
| Tool | Purpose |
|------|---------|
| `apophis_poc_list` | List PoCs in the local store, filter by CVE / source / risk |
| `apophis_poc_preview` | Show the exact cmd/env/sandbox that would be used, without executing |
| `apophis_poc_run` | Execute a PoC against a target (requires literal `confirm: true`, target in allow-list, risk ≤ max-risk) |
| `apophis_poc_history` | List past PoC executions with HMAC-verified audit records |
| `apophis_poc_kill` | Kill a running PoC execution (kill switch) |
| `apophis_poc_allowlist` | Manage the persistent allow-list of permitted targets |

A typical research-driven attack flow:

> _"Find the latest Linux kernel exploits, audit my target, and tell me which apply."_
>
> 1. `apophis_research { sources: ["cisa-kev", "exploitdb"], days_back: 30 }` → populates dynamic DB
> 2. `apophis_search_cve { keyword: "linux", min_cvss: 7.0 }` → returns matching CVEs
> 3. `apophis_audit { target: "10.10.10.1" }` → orchestrator's workers now also match against the freshly-synced dynamic DB
> 4. `apophis_recommend_exploitation { id: "<id>", severity: "CRITICAL" }` → returns exploit commands

> _"Run a known exploit PoC against the target to confirm the vulnerability."_
>
> Requires the binary to be started with `-enable-executor` and a populated `~/.apophis/allowlist.txt`.
>
> 1. `apophis_poc_list { cve: "CVE-2017-0144" }` → see candidate PoCs
> 2. `apophis_poc_preview { poc_id: "EDB-42315", target: "10.10.10.5" }` → review cmd/env/sandbox before running
> 3. `apophis_poc_run { poc_id: "EDB-42315", target: "10.10.10.5", confirm: true }` → executes inside sandbox; record is HMAC-signed
> 4. `apophis_poc_history { target: "10.10.10.5" }` → inspect past runs

---

## Research sources

| Source | What it provides | Auth |
|--------|------------------|------|
| **NVD** (NIST) | Authoritative CVEs with CVSS v3.1, CPE affected products, references. JSON API 2.0 | `APOPHIS_NVD_KEY` (optional, higher rate) |
| **CISA KEV** | Known-exploited CVEs in the wild. Critical priority list | public |
| **OSV.dev** | Open-source vulnerability database, ecosystem-agnostic | public |
| **GitHub Security Advisories** (GHSA) | Curated CVE database from the GitHub ecosystem. GraphQL API | `APOPHIS_GH_TOKEN` (optional) |
| **Exploit-DB** (offsecng mirror) | Public exploit PoCs and their CVE linkage. CSV dump | public |
| **securityweek / thehackernews / packetstorm** | RSS feeds for human-written context on emerging vulns | public |

> **Note on "hacking forums":** the request mentioned "famous hacking forums". The Apophis project deliberately sticks to public vulnerability databases and security news feeds, which is the professional, ethical, and legally-clean source of the same information. Most underground forums are illegal to access, have hostile ToS, and are not a reliable source — whereas NVD/OSV/KEV/Exploit-DB contain the same findings curated and de-duplicated.

---

## Install

```bash
git clone <this repo> apophis
cd apophis
go build -o bin/apophis ./cmd/apophis
go build -o bin/testtarget ./cmd/testtarget   # optional, for local testing
go build -o bin/mcptest ./cmd/mcptest         # optional, MCP test client
```

The binary is fully self-contained — single Go static binary, no runtime deps. To enable the PoC executor at startup, pass `-enable-executor` and prepare a target allow-list at `~/.apophis/allowlist.txt` (or override with `-allow-targets` / `-no-allowlist`).

---

## Configure in OpenCode

Edit `~/.config/opencode/opencode.json` (or your project's `opencode.jsonc`):

```jsonc
{
  "mcp": {
    "apophis": {
      "type": "local",
      "command": ["/absolute/path/to/apophis/bin/apophis"],
      "enabled": true,
      "env": {
        "APOPHIS_STORE":    "/home/YOU/.apophis/reports",
        "APOPHIS_WORKERS":  "6",
        "APOPHIS_TIMEOUT":  "5s",
        "APOPHIS_NVD_KEY":  "your-nvd-api-key-here",   // optional
        "APOPHIS_GH_TOKEN": "ghp_..."                  // optional
      }
    }
  }
}
```

Then start OpenCode. The `apophis_*` tools will appear in your tool list, ready to be called by the LLM.

Get an NVD API key (free, immediate) at <https://nvd.nist.gov/developers/request-an-api-key>.
Get a GitHub personal access token at <https://github.com/settings/tokens> (only `public_repo` scope needed).

See `opencode.jsonc.example` in this repo.

---

## Capabilities (v0.2)

### Attack (parallel multi-strategy)
- **TCP port scanning** with banner grabbing (SSH/HTTP/SMTP/FTP/POP3/IMAP heuristics)
- **TLS inspection** (version, cipher, expiry, self-signed, weak ciphers)
- **HTTP fingerprinting** (server, powered-by, title, headers, redirect chain)
- **Security-header audit** (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- **Information-disclosure path brute** with content-signature matching (`.git/`, `.env`, `.aws/credentials`, `phpinfo`, `backup.sql`, `actuator/*`)
- **Reflected XSS, SQLi, LFI / directory-traversal** checks
- **Default-credentials check** against 20+ known service defaults
- **Local static CVE matcher** with 14 high-impact vulnerabilities
- **Six exploitation strategies**: `recon`, `aggressive`, `stealth`, `web-focus`, `net-focus`, `auth-focus`
- **Persistent report store** at `~/.apophis/reports/` (JSON + Markdown, indexed)

### Research
- **Multi-source CVE sync** from NVD, OSV, CISA KEV, GHSA, Exploit-DB, security RSS feeds
- **Dynamic CVE database** at `~/.apophis/dynamic-cves.json` (auto-loaded on startup, merge-dedup on sync)
- **Live CVE matcher** in audit and `apophis_check_cve` uses BOTH static and dynamic DBs
- **Go check stub generator** for promoting a critical CVE from runtime to compiled-in
- **Baked-store path**: generated Go file can be copied to `internal/tools/cve/dynamic/baked.go` and compiled in, persisting across rebuilds

### PoC executor (opt-in, requires `-enable-executor`)
- **Three isolation levels** (auto-degrade on missing host capability):
  - **L1 (default)**: Linux namespaces (`CLONE_NEWNET`), rlimits (CPU, AS, FSIZE, NPROC, NOFILE), `NO_NEW_PRIVS`, `oom_score_adj=1000`, wrapper `ulimit` script, timeout kill
  - **L2 (opt-in, `-allow-container-sandbox`)**: runc OCI bundle (1.0.2) with all-caps-dropped, rootfs read-only, user-namespace mapping (rootless), `maskedPaths`/`readonlyPaths`
  - **L3 (stub)**: Firecracker pool with VM lifecycle (`Acquire`/`Release`/`Snapshot`/`Restore`/`Exec`), `FCMetrics{boot_ms, exec_ms, snapshot_ms, restore_ms}`; real API-socket implementation is a future PR
- **Persistent target allow-list** at `~/.apophis/allowlist.txt` — IPs, CIDR ranges, hostnames (with DNS resolution). Binary refuse-to-start without it
- **Risk classifier** with keyword heuristics (`info` / `safe` / `rce` / `destructive`), baked-in `curl|sh`, fork-bomb, `rm -rf`, `pwntools`, `msfconsole` patterns
- **HMAC-SHA256 audit log** of every execution: cmd, env, cwd, rlimits, namespaces, stdout, stderr, exit code, duration, sha256 of the PoC. Records are 0444 + HMAC; tampering is detected on read
- **Strict validation in the MCP handler**:
  - `confirm` must be the literal boolean `true` (the JSON schema rejects string `"true"`)
  - target must be in the allow-list
  - PoC risk must not exceed `-max-risk` configured at startup
  - `sandbox_level` must be enabled at startup
  - `timeout_sec` must not exceed `-execution-timeout`
- **Integrations (Phase 6)**:
  - **Metasploit**: hand-rolled msgpack-rpc client to `msfrpcd`; PoCs with `Source = "metasploit"` are dispatched as `module.execute(exploit, ...)`; config via `-msfrpc-url` / `-msfrpc-user` / `-msfrpc-pass`
  - **Nuclei**: spawns `nuclei -t <template> -u <target> -json-export -` inside the sandbox; PoCs with `Source = "nuclei"` go through this path
  - **Boofuzz**: spawns `python3 <script> --target <target>` with the configured timeout
- **Six new MCP tools** for the LLM: `apophis_poc_list`, `apophis_poc_preview`, `apophis_poc_run`, `apophis_poc_history`, `apophis_poc_kill`, `apophis_poc_allowlist`
- **Dry-run mode** (`-dry-run-executor`): every PoC run is a stub that returns exit 0, no real execution
- **Kill switch**: `apophis_poc_kill` aborts a running execution by `execution_id`

See [`docs/POC_EXECUTOR.md`](docs/POC_EXECUTOR.md) for the full design.

---

## Architecture

```
cmd/
  apophis/      MCP server entry point (this is what OpenCode spawns)
  mcptest/      Tiny MCP client used for development testing
  testtarget/   Intentionally vulnerable test server for offline testing

internal/
  mcp/          Tool definitions + JSON-RPC handlers
  orchestrator/ Fan-out / fan-in of chaos agents
  worker/       Chaos agent — runs phases filtered by strategy
  store/        File-based report persistence with index
  research/
    agent.go    Orchestrates parallel fetch from N sources, dedupes, persists
    generator.go Emits Go check stubs / baked-store file
    sources/    Adapters: NVD, CISA KEV, OSV, GHSA, Exploit-DB, RSS
  tools/
    network/    TCP port scanner with banner grabbing
    web/        HTTP scanner + path brute + LFI/SQLi/XSS checks
    ssl/        TLS inspector
    auth/       Default-credentials tester
    cve/        Static + matcher (uses both static DB and dynamic.Store)
      dynamic/  Runtime CVE database with persistence + baked entries
  poc/          PoC executor (opt-in)
    types.go        PoC, RiskLevel, PoCType, SandboxLevel, ExecConfig, AuditRecord
    classifier.go   Keyword-based risk classification (info / safe / rce / destructive)
    allowlist.go    IP + CIDR + hostname allow-list, persistent file format
    audit.go        Append-only JSON log with HMAC-SHA256, tamper detection
    sandbox_linux.go    L1 sandbox: namespaces + rlimits + NO_NEW_PRIVS
    sandbox_other.go    Stub for non-Linux hosts
    runc_sandbox.go     L2 runc OCI bundle (config.json with all-caps dropped, rootless)
    runc_sandbox_other.go  Stub for non-Linux hosts
    firecracker_sandbox.go  L3 microVM stub (pool, metrics, TODO API socket)
    executor.go     Orchestrator: validate → audit → dispatch (L1/L2/integration) → audit
    integrations.go MSFRPC (hand-rolled msgpack-rpc), NucleiDispatcher, BoofuzzDispatcher
    fetch.go        Exploit-DB PoC downloader (raw + GitHub mirror)
    store.go        PoC persistence
    state.go        Shared state bundle (Allowlist + Audit + Store + Executor)
  report/       Markdown + JSON writer
  models/       Domain types
  logger/       Color-coded structured logger (writes to stderr)
```

A run is a single **fan-out / fan-in** orchestrated by `internal/orchestrator`:

1. The orchestrator picks N strategies from a pool (one per worker) and spawns them as goroutines.
2. Each worker runs its own pipeline (`portScan → ssl → web → auth → cve`) filtered by its strategy.
3. The orchestrator collects `worker.Result` values from a channel, merges and dedupes findings, scores them and emits a `Report`.
4. The store persists the report to `~/.apophis/reports/rpt-<id>.{json,md}` and updates the index.

A research sync is a separate **fan-out / fan-in** orchestrated by `internal/research`:

1. The agent spawns N source workers in parallel, each fetching its own data.
2. Findings are normalized to a common `Finding` type regardless of source.
3. Dedupe merges by CVE id, preferring higher CVSS / more data.
4. The dynamic store is updated (`added`, `updated`).
5. If `generate_stubs=true`, Go source is written for the entire dynamic DB.

---

## Roadmap

- [x] **Sandboxed PoC executor** (L1 + L2 runc, opt-in) — implemented in `internal/poc/`
- [x] **Metasploit / nuclei / boofuzz integrations** — implemented as dispatchers
- [x] **Allow-list + HMAC audit log** — implemented
- [ ] HTTP transport alongside stdio
- [ ] UDP scanning
- [ ] SMB / LDAP / SNMP / FTP specific deep checks
- [ ] nuclei-template-compatible signature loader
- [ ] **Firecracker L3 real implementation** (API socket, vsock, snapshot+restore)
- [ ] **AI-driven strategy selection** (LLM picks which agents to spawn based on target profile)
- [ ] **Vector DB / embeddings** for semantic CVE similarity search
- [ ] TUI dashboard
- [ ] Plugin system for community strategies

---

## Ethics

> **Run APOPHIS only against systems you own or have explicit written permission to test.**
>
> Unauthorised scanning and exploitation is illegal in most jurisdictions (CFAA, Computer Misuse Act, etc.). APOPHIS comes with no warranty and the author is not responsible for misuse. The tool exists to help defenders find their weaknesses before attackers do.

---

## License

MIT
