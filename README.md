# APOPHIS — Vulnerability Chaos Engine

> **Apophis** (Apep) is the Egyptian serpent-god of chaos, the eternal adversary of Ra who threatens to swallow the sun and unravel order. This engine channels that same relentless chaos against misconfigured, vulnerable, or exposed systems — and actively hunts for new weaknesses to break.

A **Model Context Protocol (MCP) server** for [OpenCode](https://github.com/sst/opencode) and any MCP-compatible AI client.

- **Parallel chaos agents** race against a target from different angles (recon, aggressive, stealth, web-focus, net-focus, auth-focus) and consolidate findings into structured reports
- **Deep protocol probes**: SMBv1 (EternalBlue pre-condition), LDAP/LDAPS rootDSE, SNMPv2c community brute, FTP anonymous / weak creds, UDP service probing (DNS, NTP, SNMP, NetBIOS-NS, TFTP, SIP)
- **AI-driven strategy planner** (rule-based, profile-aware) picks the optimal strategy mix from the discovered service surface
- **Integrated vulnerability research agent** that syncs CVEs and exploit PoCs from public sources (NVD, OSV, CISA KEV, GitHub Security Advisories, Exploit-DB, security RSS feeds) and updates the local database
- **CVE → exploit link** that joins every CVE finding with available PoCs (local store), Metasploit modules and Exploit-DB entries — and feeds the evidence into the report
- **TF-IDF similarity search** over the CVE database for free-text "find me CVEs like X" queries
- **Threat-intel enrichment**: GreyNoise, Shodan InternetDB (keyless), AbuseIPDB, VirusTotal — fold the verdicts into every audit
- **nuclei-template-compatible loader** with a hand-rolled YAML parser and ~25 bundled templates for the most common exposures
- **Stealth mode**: adaptive rate limiter + jitter, decoy routing, WAF / CDN fingerprinting (Cloudflare, Akamai, AWS, Imperva, F5, Sucuri, ModSecurity, etc) and an evasion-profile knob (off/low/medium/high)
- **Exploit tool generator** that produces ready-to-paste Go check stubs for new CVEs
- **Sandboxed PoC executor** with three isolation levels (Linux namespaces → runc container → Firecracker microVM), HMAC-signed audit log, persistent allow-list, and integrations for Metasploit (msfrpcd), nuclei, and boofuzz

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
| `apophis_audit` | Full multi-strategy parallel scan (optionally stealthy / AI-planned / WAF-aware), returns report id + summary |
| `apophis_portscan` | Quick TCP port scan + banner grab (and optional UDP) |
| `apophis_udp_scan` | UDP scan with protocol-specific probes (DNS / NTP / SNMP / NetBIOS-NS / TFTP / SIP) |
| `apophis_web_audit` | Focused web app audit (headers, paths, LFI/SQLi/XSS, TLS, nuclei run) |
| `apophis_smb_audit` | SMBv1 / signing / null-session / share-enum / OS disclosure |
| `apophis_ldap_audit` | LDAP / LDAPS anonymous bind, rootDSE fingerprint, signing / sealing |
| `apophis_snmp_audit` | SNMPv2c community-string brute (public / private / manager / monitor / …) |
| `apophis_ftp_audit` | FTP anonymous login, weak credentials, STARTTLS, SYST disclosure |
| `apophis_waf_detect` | Identify the WAF / CDN in front of a URL (Cloudflare, Akamai, AWS, Imperva, F5, Sucuri, ModSecurity, …) |
| `apophis_threatintel` | Look up an IP / host in GreyNoise, Shodan InternetDB, AbuseIPDB, VirusTotal |
| `apophis_check_cve` | Match a service+version+banner against the **combined** static + dynamic CVE database, with linked exploits |
| `apophis_similar_cve` | TF-IDF similarity search over the CVE database for free-text queries |
| `apophis_recommend_exploitation` | Look up exploit guides for findings (with PoC / Metasploit / Exploit-DB refs) |
| `apophis_list_reports` | List all stored reports (filter by target substring) |
| `apophis_get_report` | Retrieve a stored report (summary / findings / json) |
| `apophis_delete_report` | Delete a report |

### Authentication attacks
| Tool | Purpose |
|------|---------|
| `apophis_asrep_roast` | Probe AD accounts for DONT_REQUIRE_PREAUTH (AS-REP-roastable) |
| `apophis_kerberoast` | Inventory + prioritise SPN-holding service accounts (Kerberoasting target list) |
| `apophis_delegation_audit` | Detect unconstrained / constrained / RBCD Kerberos delegation abuse |
| `apophis_ntlm_dialects` | Probe NTLMSSP dialect weakness (LM, OEM, no signing, no 128-bit) |
| `apophis_password_policy` | Score the AD password policy (length, lockout, complexity) |
| `apophis_spray` | Generate a targeted password-spray wordlist seeded with company name |
| `apophis_jwt_attack` | Inspect a JWT for alg=none, RS↔HS confusion, kid traversal, JWK injection |
| `apophis_jwt_brute` | Brute-force an HS256/384/512 JWT secret against the bundled top-1000 weak list |
| `apophis_saml_attack` | Inspect a SAML Response for XSW, comment injection, weak signatures, replay |
| `apophis_oauth_audit` | OAuth / OIDC config audit (open-redirect, missing / weak state, wildcard redirect_uri) |
| `apophis_auth_audit` | Web auth flow audit (cookie flags, CSRF, password-reset Host header, rate-limit) |
| `apophis_cred_leak` | Credential-leak probes (entropy / hardcoded / backup files / .git / commit messages) |

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
        "APOPHIS_STORE":          "/home/YOU/.apophis/reports",
        "APOPHIS_WORKERS":        "6",
        "APOPHIS_TIMEOUT":        "5s",
        "APOPHIS_NVD_KEY":        "your-nvd-api-key-here",   // optional
        "APOPHIS_GH_TOKEN":       "ghp_...",                  // optional
        "APOPHIS_GREYNOISE_KEY":  "your-greynoise-key",       // optional
        "APOPHIS_SHODAN_KEY":     "your-shodan-key",          // optional (InternetDB is free)
        "APOPHIS_ABUSEIPDB_KEY":  "your-abuseipdb-key",       // optional
        "APOPHIS_VIRUSTOTAL_KEY": "your-virustotal-key"       // optional
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

## Capabilities (v0.3)

### Attack (parallel multi-strategy)
- **TCP port scanning** with banner grabbing (SSH/HTTP/SMTP/FTP/POP3/IMAP heuristics)
- **UDP port scanning** with protocol-specific probes (DNS / NTP / SNMP / NetBIOS-NS / TFTP / SIP); "open|filtered" vs "open" is distinguished on positive service replies
- **TLS inspection** (version, cipher, expiry, self-signed, weak ciphers)
- **HTTP fingerprinting** (server, powered-by, title, headers, redirect chain)
- **Security-header audit** (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy)
- **Information-disclosure path brute** with content-signature matching (`.git/`, `.env`, `.aws/credentials`, `phpinfo`, `backup.sql`, `actuator/*`)
- **Reflected XSS, SQLi, LFI / directory-traversal** checks
- **Default-credentials check** against 20+ known service defaults (HTTP) and per-protocol defaults (FTP, SNMP)
- **SMB deep checks**: SMBv1 negotiation (EternalBlue pre-condition), SMB2 signing-required enforcement, null-session, NetShareEnum share listing, OS version disclosure
- **LDAP / LDAPS deep checks**: anonymous bind over cleartext, rootDSE fingerprint (Active Directory / OpenLDAP / 389 DS), default-naming-context leak, supportedSASLMechanisms (signing / sealing)
- **SNMPv2c community-string brute** against UDP/161 (public, private, manager, monitor, admin, snmp, cisco, secret, rw, ro, …)
- **FTP deep checks**: anonymous login, weak credentials (admin / root / ftp / test), STARTTLS advertised, SYST disclosure
- **nuclei-template loader** (built-in mini-YAML parser, ~25 bundled templates + any user `.yaml` files pointed to by `-nuclei-templates`): exposed `.env`, exposed `.git/config`, phpinfo, Jenkins script-console, Tomcat manager, log4shell probes, FortiOS / Citrix / F5 BIG-IP RCEs, Traefik dashboard, WordPress debug.log, …
- **Local static CVE matcher** with 14 high-impact vulnerabilities
- **Six exploitation strategies + AI-planned**: `recon`, `aggressive`, `stealth`, `web-focus`, `net-focus`, `auth-focus`, `ai-planned`
- **AI-driven planner**: rule-based, profile-aware (always recon + web-focus if HTTP detected + stealth if WAF detected + aggressive if SMB / SNMP detected + auth-focus if SSH / RDP / LDAP detected)
- **Persistent report store** at `~/.apophis/reports/` (JSON + Markdown, indexed)

### Research & intelligence
- **Multi-source CVE sync** from NVD, OSV, CISA KEV, GHSA, Exploit-DB, security RSS feeds
- **Dynamic CVE database** at `~/.apophis/dynamic-cves.json` (auto-loaded on startup, merge-dedup on sync)
- **TF-IDF vector index** over the CVE database (`apophis_similar_cve`) for free-text similarity search — no external embedding service needed
- **CVE → exploit link**: every finding carries the PoCs available locally + the Metasploit modules + the Exploit-DB entries (curated catalog of 15 high-signal CVEs)
- **Live CVE matcher** in audit and `apophis_check_cve` uses BOTH static and dynamic DBs
- **Go check stub generator** for promoting a critical CVE from runtime to compiled-in
- **Baked-store path**: generated Go file can be copied to `internal/tools/cve/dynamic/baked.go` and compiled in, persisting across rebuilds
- **Threat-intel feeds**:
  - **Shodan InternetDB** (keyless) — exposed ports, CVEs assigned to the IP, ASN, geo
  - **GreyNoise Community** — mass-scanner / benign / suspicious / malicious classification
  - **AbuseIPDB** — abuse-confidence score, ISP, usage type
  - **VirusTotal** — last-analysis-stats verdict across 70+ AV engines
  - Verdicts are merged into every finding (`threatintel:<source>` tags) and surfaced in the report summary

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
  orchestrator/ Fan-out / fan-in of chaos agents + threat-intel enrichment
  planner/      AI-driven strategy selection (rule-based)
  worker/       Chaos agent — runs phases filtered by strategy
  store/        File-based report persistence with index
  stealth/      Adaptive pacer, decoy router, WAF detector, evasion profile
  threatintel/  GreyNoise / Shodan / AbuseIPDB / VirusTotal adapters
  auth/         Authentication attacks: AS-REP / Kerberoast / Delegation / NTLMSSP / PasswordPolicy / Spray (Bucket A)
  tokens/       JWT / OAuth / SAML attacks (Bucket B)
  webauth/      Cookie / CSRF / password-reset / rate-limit / 2FA (Bucket C)
  credleak/     Entropy / hardcoded / backup files / .git (Bucket D)
  research/
    agent.go    Orchestrates parallel fetch from N sources, dedupes, persists
    generator.go Emits Go check stubs / baked-store file
    sources/    Adapters: NVD, CISA KEV, OSV, GHSA, Exploit-DB, RSS
  tools/
    network/    TCP + UDP port scanners with banner grabbing
    web/        HTTP scanner + path brute + LFI/SQLi/XSS checks
    ssl/        TLS inspector
    auth/       Default-credentials tester
    smb/        SMBv1 / signing / null-session / share-enum / OS disclosure
    ldap/       LDAP / LDAPS anonymous bind + rootDSE fingerprint
    snmp/       SNMPv2c community-string brute
    ftp/        FTP anonymous / weak creds / STARTTLS / SYST
    nuclei/     Built-in mini nuclei-template parser + ~25 bundled templates
    cve/        Static + matcher (uses both static DB and dynamic.Store)
      dynamic/      Runtime CVE database with persistence + baked entries
      embeddings/   TF-IDF vector index for similarity search
      exploitlink/  CVE → PoC / Metasploit / Exploit-DB linkage
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
  models/       Domain types (Finding now carries Tags, ThreatIntel, ExploitRefs)
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

## Authentication attacks (v0.4)

The most impactful area in any real pentest. Apophis ships a dedicated
auth-attack engine split into four attack buckets, each with its own
package and a set of MCP tools.

### A. Active Directory / Kerberos (`internal/auth/`)
- **AS-REP roasting** (`apophis_asrep_roast`) — unauthenticated detection of accounts with `DONT_REQUIRE_PREAUTH`. Sends AS-REQ with no padata, parses AS-REP / KRB-ERROR, flags RC4-HMAC responses as offline-crackable (hashcat -m 7500).
- **Kerberoasting scaffold** (`apophis_kerberoast`) — SPN inventory + prioritisation (password age, admin count, RC4 etype). Operator-supplied TGT triggers the actual TGS-REQ.
- **Delegation abuse** (`apophis_delegation_audit`) — given LDAP attributes, finds accounts with `TRUSTED_FOR_DELEGATION` (unconstrained, 0x80000), `TRUSTED_TO_AUTH_FOR_DELEGATION` (S4U2Self, 0x1000000), `msDS-AllowedToDelegateTo` (constrained), `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD).
- **NTLMSSP dialect weakness** (`apophis_ntlm_dialects`) — connects to SMB/445 (and optional HTTP), parses the negotiated flags, scores the dialect (LM, OEM-only, no NTLM, no signing, no 128-bit).
- **Password policy** (`apophis_password_policy`) — given Default Domain Policy attributes, scores length / lockout / complexity / reversibility / max-age.
- **Spray wordlist generator** (`apophis_spray`) — company name + active year + seasons + common defaults → deduped, capped wordlist ready for the executor.

### B. JWT / OAuth / SAML (`internal/tokens/`)
- **JWT inspect** (`apophis_jwt_attack`) — decodes a JWT, flags `alg=none`, RS↔HS confusion with embedded JWK, `kid` path traversal / SQL injection, `x5u` URL inclusion, expired tokens.
- **JWT weak-secret brute** (`apophis_jwt_brute`) — tries the bundled top-1000 weak HMAC secrets against HS256/384/512 tokens; reports the recovered secret.
- **SAML inspect** (`apophis_saml_attack`) — detects XSW (multiple `<Assertion>` in one Response), comment injection, weak signature algorithm (SHA-1), missing / expired `NotOnOrAfter`, missing `NotBefore`, missing `<NameID>`.
- **OAuth audit** (`apophis_oauth_audit`) — wildcard `redirect_uri`, origin drift against the registered allow-list, missing or short `state`.

### C. Web auth flows (`internal/webauth/`)
- **Cookie attribute audit** — `Secure`, `HttpOnly`, `SameSite`, scope. Auto-detects session cookies by name.
- **CSRF token check** — passes the expected param name; flags absence and short / low-entropy values.
- **Password-reset Host-header template detection** — flags URLs that contain `{HOST}` / `<host>` tokens (the classic Host-header-injection pattern) and plain-HTTP reset links.
- **Login rate-limit / lockout** — given a sequence of failed-login responses, flags endpoints that don't return 429, `Retry-After`, or a "locked" message.
- **2FA enforcement gap** — given a list of sensitive subpaths, flags the absence of an MFA step on those paths.
- **Backup code brute surface** — given the number / length of issued backup codes and the observed rate-limit state, computes the expected number of guesses per success.

### D. Credential leaks (`internal/credleak/`)
- **Entropy detector** — Shannon-entropy regex on credential-shaped keys (`password`, `api_key`, `secret`, …).
- **Hardcoded credentials** — bundled catalog of 25+ patterns: AWS access keys (`AKIA…`), GitHub PATs (`ghp_…`), Slack tokens (`xoxb-…`), Stripe live keys (`sk_live_…`), OpenAI (`sk-…`), private keys, JWTs, Twilio, SendGrid, npm, PyPI, …
- **Backup file enumeration** — 60+ candidate paths: `.env`, `.aws/credentials`, `.pgpass`, `.npmrc`, `id_rsa`, `wp-config.php.bak`, `phpinfo.php`, `.git/HEAD`, `.docker/config.json`, `debug.log`, `swagger.json`, …
- **`.git` directory scan** — `.git/HEAD`, `.git/config`, `.git/index`, `.git/logs/HEAD`, `.git/refs/heads/*`, `.git/packed-refs`. Detects when the repo is downloadable.
- **Commit-message leak** — scans `.git/COMMIT_EDITMSG` and `.git/logs/HEAD` for embedded credentials in commit messages.

### Wiring
All four buckets are auto-invoked by `apophis_audit` when the relevant
strategy is selected:
- `web-focus` + `aggressive` + `auth-focus` → runs `auth_attack` (cookies, CSRF, host-header, NTLMSSP, JWTs in page bodies)
- `web-focus` + `aggressive` + `auth-focus` + `recon` + `net-focus` → runs `cred_leak` (backup files, .git, hardcoded creds, entropy on every fetched body)

Each bucket also has its own dedicated MCP tool (`apophis_auth_audit`,
`apophis_cred_leak`, `apophis_asrep_roast`, etc.) so an LLM agent can drill
into one vector at a time.

## Stealth & evasion

- **Adaptive rate limiter**: per-second probe budget, in-flight semaphore, jitter; on timeout / refusal surges the limiter automatically slows down (×1.25 → ×6.0) until the target recovers
- **Per-strategy default rate**: `stealth` = 5/s with 50ms jitter; `recon` = 30/s; `aggressive` = unlimited
- **Decoy routing**: supply a comma-separated list of decoy hosts (`apophis_audit decoys="1.1.1.1,scanme.sh"`) and Apophis issues benign GETs to the decoys in parallel to dilute the audit trail
- **WAF / CDN fingerprinting**: `apophis_waf_detect` sends a baseline + a malicious payload and matches Cloudflare (`cf-ray`), AWS WAF (`x-amzn-waf`), Akamai, Imperva, F5 (`x-wa-info`), Sucuri, ModSecurity (`OWASP CRS`), Barracuda, Wordfence, Fastly, CloudFront
- **Evasion profile** (`off` / `low` / `medium` / `high`): rotates User-Agent strings, randomises Accept-Language, applies `gzip`/`deflate` Accept-Encoding, randomises query strings
- **When the audit detects a WAF**: the planner automatically includes `stealth` in the strategy mix

## Roadmap

- [x] **Sandboxed PoC executor** (L1 + L2 runc, opt-in) — implemented in `internal/poc/`
- [x] **Metasploit / nuclei / boofuzz integrations** — implemented as dispatchers
- [x] **Allow-list + HMAC audit log** — implemented
- [x] **UDP scanning** — implemented in `internal/tools/network/udp.go`
- [x] **SMB / LDAP / SNMP / FTP specific deep checks** — implemented
- [x] **nuclei-template-compatible signature loader** — implemented (built-in mini-parser, ~25 bundled templates)
- [x] **AI-driven strategy selection** — implemented (rule-based, profile-aware)
- [x] **Vector DB / embeddings** — implemented (TF-IDF, no external deps)
- [x] **Threat-intel feeds** — implemented (GreyNoise, Shodan, AbuseIPDB, VirusTotal)
- [x] **Stealth / WAF fingerprinting / evasion profiles** — implemented
- [x] **Authentication attacks** — implemented (`internal/auth/`, `internal/tokens/`, `internal/webauth/`, `internal/credleak/`)
- [ ] HTTP transport alongside stdio
- [ ] **Firecracker L3 real implementation** (API socket, vsock, snapshot+restore)
- [ ] TUI dashboard
- [ ] Plugin system for community strategies
- [ ] Real nuclei binary delegation (the built-in loader is the fallback)

---

## Ethics

> **Run APOPHIS only against systems you own or have explicit written permission to test.**
>
> Unauthorised scanning and exploitation is illegal in most jurisdictions (CFAA, Computer Misuse Act, etc.). APOPHIS comes with no warranty and the author is not responsible for misuse. The tool exists to help defenders find their weaknesses before attackers do.

---

## License

MIT
