# APOPHIS — PoC Executor

> **Estado:** implementado. Fases 1-3 (foundation, MCP integration, hardening) y 4-6 (runc, Firecracker stub, integrations) están en el repositorio bajo `internal/poc/`. Phase 5 (Firecracker) es un stub explícito con API-socket marcado como TODO.
> **Audiencia:** mantenedores y operadores de Apophis que vayan a habilitar el módulo de ejecución de exploits.
> **Objetivo:** definir cómo Apophis debe ejecutar PoCs (Proofs-of-Concept) obtenidos por el agente de investigación de forma **segura, observable y reversible**, y servir como referencia de lo que está implementado.

---

## 0. Por qué este documento existe

APOPHIS v0.2 puede **descubrir** vulnerabilidades y **recomendar** pasos de explotación, pero **no ejecuta nada** sobre el objetivo. El siguiente paso lógico es ejecutar los PoCs publicados (Exploit-DB, GHSA, NVD references) para confirmar de forma empírica si la vulnerabilidad es real en el target concreto.

Ejecutar código hostil es cualitativamente distinto a escanear. Un PoC con `-O0` puede:

- hacer un fork-bomb y tumbar el host del auditor
- pivotar al bastion de la red interna
- exfiltrar el `.ssh/id_rsa` del usuario que corre Apophis
- hacer cryptomining o DoS
- usarse como vector de supply-chain attack (PoC "envenenado")

Este documento define **cómo minimizar ese riesgo** sin dejar de cumplir la función de verificación.

---

## 1. Principios no negociables

Estos principios se aplican **antes** de cualquier decisión técnica. Si una decisión los viola, está mal tomada.

1. **No hay valor por defecto.** El executor viene deshabilitado. Para activarlo hace falta un flag explícito en el arranque del binario (`-enable-executor`) y otro flag por cada invocación (`confirm: true` en el payload MCP).
2. **El usuario es responsable del target.** Antes de la primera ejecución, Apophis exige que el operador haya tipeado literalmente el hostname/IP a atacar y que ese host esté en una allow-list persistente.
3. **El aislamiento es la primera línea de defensa, no la única.** Asumimos que el sandbox puede ser vulnerado. Por eso hay auditoría, rate limits, kill switch, y el binario corre con un usuario dedicado sin privilegios.
4. **La ejecución es observable y reproducible.** Cada PoC ejecutado deja un JSON inmutable con `cmd, env, pwd, ulimits, namespaces, stdout, stderr, exit_code, duration, sha256(poc)`.
5. **Nada se ejecuta offline sin log.** Si no podemos escribir el audit log, abortamos.
6. **Reversibilidad.** El estado del sandbox (filesystem, red) se descarta tras cada PoC. No se permite que un PoC modifique el host del auditor.

---

## 2. Arquitectura propuesta

```
                        ┌──────────────────────┐
                        │  MCP host (LLM)      │
                        └──────────┬───────────┘
                                   │ apophis_poc_run / apophis_poc_preview
                                   ▼
                        ┌──────────────────────┐
                        │  apophis (MCP srv)   │
                        │  --enable-executor   │
                        └──────────┬───────────┘
                                   │
                                   ▼
                        ┌──────────────────────┐
                        │   Executor core      │
                        │   (policies, ACL,    │
                        │    limits, audit)    │
                        └──────────┬───────────┘
                                   │
                ┌──────────────────┼──────────────────┐
                ▼                  ▼                  ▼
        ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
        │ Sandbox L1   │   │ Sandbox L2   │   │ Sandbox L3   │
        │ subprocess   │   │ container    │   │ microVM      │
        │ + namespaces │   │ (runc/Docker)│   │ (Firecracker)│
        │ + rlimits    │   │              │   │              │
        │ (default)    │   │ (opt-in)     │   │ (futuro)     │
        └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
               │                  │                  │
               ▼                  ▼                  ▼
        ┌──────────────────────────────────────────────────┐
        │           Target (que el operador escribió)      │
        └──────────────────────────────────────────────────┘
```

Tres niveles de aislamiento, todos disponibles en Linux:

- **L1 — Subprocess + namespaces** (default): `os/exec` con `SysProcAttr{Cloneflags: CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWUTS}`, `rlimit` estricto, `prctl(PR_SET_NO_NEW_PRIVS)`, sin setuid. Sin instalación adicional.
- **L2 — Container** (opt-in): arranca un `runc` / `crun` efímero con la imagen `apophis/sandbox:stable`, network=none, read-only-rootfs, user-namespace. Requiere que el host tenga `runc` instalado.
- **L3 — microVM** (futuro): [Firecracker](https://github.com/firecracker-microvm/firecracker) por PoC, guest kernel mínimo, snapshot+restore. Más fuerte pero ~150ms de overhead.

Por defecto L1. El LLM puede pedir L2 vía `sandbox_level: "container"` en el payload (si el binario se arrancó con `-allow-container-sandbox`). L3 se implementa después.

---

## 3. Modelo de datos (PoC)

```go
// internal/poc/poc.go
type PoC struct {
    ID          string    // "EDB-12345" | "CVE-2024-12345" | "custom-<sha256>"
    Source      string    // "exploitdb" | "ghsa" | "nvd" | "manual"
    CVE         string
    Title       string
    Author      string
    Type        PoCType   // shell | python | ruby | js | binary | nuclei | msf | curl
    Path        string    // filesystem path (sandbox-local, después de fetch)
    Raw         string    // código fuente
    Args        []string  // CLI args, saneados
    Env         []string  // KEY=val, saneados
    Risk        RiskLevel // info | safe | rce | destructive
    RequiresNet bool      // ¿necesita conectividad al target?
    Signature   string    // sha256 de Raw, para auditoría
}

type RiskLevel int
const (
    RiskInfo        RiskLevel = 0  // solo lectura, ningún side-effect
    RiskSafe        RiskLevel = 1  // puede crear archivos en el sandbox
    RiskRCE         RiskLevel = 2  // ejecuta código en el target
    RiskDestructive RiskLevel = 3  // puede romper el target
)
```

### Reglas de categorización de riesgo

Un PoC se clasifica **al fetch** (al descargarlo) mirando keywords estáticas sobre el código:

| Heurística | Riesgo |
|------------|--------|
| palabras `print`, `read`, `get`, `cve-` | `info` |
| `connect`, `socket`, `http` | `safe` |
| `exec`, `subprocess`, `system`, `os.system`, `cmd`, `/bin/sh`, `pwntools`, `msfconsole` | `rce` |
| `rm -rf`, `mkfs`, `dd if=`, `:(){:|:&};:` (fork bomb), `curl \| sh`, `drop table`, `shutdown` | `destructive` |

Esto **no es infalible**. Es una primera barrera. Un PoC de "info" puede contener `eval()` y romperse. Por eso la regla 3 de la sección 1: **asumimos que el sandbox puede ser vulnerado**.

---

## 4. Sandbox L1 — Subprocess con namespaces

### Capacidades
- Filesystem: `chroot` o `pivot_root` a un directorio temporal con busybox mínimo + el PoC + librerías necesarias (Python stdlib, libssl, libpcap).
- Red: por defecto, **sin red**. Si el PoC requiere red, se le concede **solo** acceso al target especificado vía proxy ARP/NAT dentro del namespace.
- PIDs: namespace propio, no ve los procesos del host.
- Mount: read-only excepto `/tmp` del sandbox.
- Ulimits: `RLIMIT_CPU=60s`, `RLIMIT_AS=512MB`, `RLIMIT_FSIZE=64MB`, `RLIMIT_NPROC=32`, `RLIMIT_NOFILE=64`.
- Capabilities: drop ALL; `CAP_NET_RAW` solo si `RequiresNet`.
- Seccomp: blacklist agresiva, ejemplo `kexec_load`, `init_module`, `mount`, `umount2`, `bpf`, `userfaultfd`, `perf_event_open`.
- Tiempo de vida: max 5 minutos por defecto (configurable), killed con SIGKILL si excede.
- `oom_score_adj = 1000` para que el kernel lo mate primero si hay presión de memoria.

### Implementación
- `internal/poc/sandbox_linux.go` con `syscall.SysProcAttr{Cloneflags: ...}` y la batería de `prctl`, `seccomp`, `setrlimit`.
- `internal/poc/runc_sandbox.go` para L2.
- Detección automática de capabilities del kernel: si no hay `user_namespaces` habilitados, se degrada a L2 o se niega.
- Test: `TestSandbox_NoNetwork` que verifica que el PoC no puede hacer `connect(2)` a un socket externo.

### Lo que NO hace L1
- No protege contra **vulnerabilidades del kernel**. Si el PoC explota CVE-2022-0847 (Dirty Pipe) y se ejecuta como root del namespace, puede escapar.
- No oculta el código del binario. Si el operador corre Apophis con su `~/.ssh/id_rsa` montado, el PoC puede leerlo.

**Mitigaciones:**
- Apophis corre con un usuario dedicado `apophis-exec` con `chmod 700` en su `~`, sin acceso a `$HOME/.ssh`, `$HOME/.gnupg`, etc.
- El binario refuse-to-run como root (`uid==0`) a menos que se pase `-allow-root` (para setups de CI).
- Se monta `/proc/sysrq-trigger` como read-only y se desactiva `ptrace_scope` (`/proc/sys/kernel/yama/ptrace_scope=3`).

---

## 5. Audit log

Cada ejecución produce un JSON append-only en `~/.apophis/executions/<timestamp>-<id>.json`:

```json
{
  "id": "exe-1780872187466964320",
  "started_at": "2026-06-07T19:43:07Z",
  "finished_at": "2026-06-07T19:43:08Z",
  "duration_ms": 812,
  "poc": {
    "id": "EDB-51015",
    "cve": "CVE-2023-50164",
    "type": "python",
    "signature": "sha256:9a3f...",
    "risk": "rce",
    "source": "exploitdb"
  },
  "target": "10.10.10.5",
  "sandbox": {
    "level": "L1",
    "namespaces": ["mnt", "pid", "net", "uts"],
    "rlimits": {"cpu": 60, "as": 536870912, "nproc": 32},
    "seccomp": "apophis-strict-v1"
  },
  "cmd": ["python3", "/sandbox/poc.py", "10.10.10.5", "8080"],
  "env": ["HOME=/sandbox", "PATH=/sandbox/bin"],
  "exit_code": 0,
  "signal": "",
  "stdout": "...\n",
  "stderr": "",
  "exploit_verified": true,
  "vuln_confirmed": true,
  "user_confirmed_at": "2026-06-07T19:42:55Z"
}
```

Estos logs:
- Son **inmutables** (permisos 0444 una vez escritos).
- Se firman con HMAC usando un secret en `~/.apophis/exec-secret.key` para detectar tampering.
- Se suben opcionalmente a un SIEM (configurable).

---

## 6. Herramientas MCP nuevas

| Tool | Input | Output |
|------|-------|--------|
| `apophis_poc_list` | `{cve, source, min_risk, max_risk, limit}` | lista de PoCs conocidos (de la DB local) |
| `apophis_poc_preview` | `{poc_id, target, sandbox_level}` | muestra comando exacto, env, límites, sin ejecutar. Devuelve `cmd`, `estimated_risk`, `warnings` |
| `apophis_poc_run` | `{poc_id, target, sandbox_level, timeout_sec, confirm: true}` | ejecuta, devuelve `execution_id` + resultado. **Requiere `confirm: true` literal.** |
| `apophis_poc_history` | `{target, since, limit}` | lista ejecuciones previas con resultados |
| `apophis_poc_kill` | `{execution_id}` | mata la ejecución en curso (kill switch) |
| `apophis_poc_allowlist` | `{action: "add"\|"list"\|"remove", target, note}` | gestiona hosts permitidos |

**Reglas de validación en el handler:**

- `confirm: true` debe estar presente **y** ser un bool literal, no string.
- El `target` debe estar en la allow-list.
- El `risk` del PoC no puede superar el `max_risk` configurado en el binario (default `RCE`, opt-in para `DESTRUCTIVE`).
- `sandbox_level` debe ser ≤ el nivel máximo habilitado al arrancar.
- `timeout_sec` no puede exceder el máximo global.

Si cualquier regla falla → `errorResult(...)` con código de error específico, sin ejecutar nada.

---

## 7. CLI / arranque

```
apophis \
  -enable-executor \
  -max-risk destructive \
  -allow-container-sandbox \
  -executor-user apophis-exec \
  -execution-timeout 300s
```

Flags relevantes:

| Flag | Default | Significado |
|------|---------|-------------|
| `-enable-executor` | `false` | off-by-default, hay que activarlo |
| `-max-risk` | `rce` | `info` \| `safe` \| `rce` \| `destructive` |
| `-allow-container-sandbox` | `false` | habilita L2 |
| `-executor-user` | `apophis-exec` | uid bajo el que corren los PoCs |
| `-execution-timeout` | `5m` | kill por timeout |
| `-allow-targets` | (allowlist path) | archivo con targets permitidos |
| `-dry-run-executor` | `false` | todos los PoC se ejecutan en stub (devuelven exit 0) |

---

## 8. Allow-list de targets

Archivo `~/.apophis/allowlist.txt` con un target por línea:

```
# formato: TARGET [NOTE]
10.10.10.5     # lab-htb-foxy
10.10.11.0/24  # red de práctica VulnHub
scanme.nmap.org
192.168.1.0/24 # mi LAN
```

Soporta:
- IPs exactas
- CIDR (`10.10.11.0/24`)
- Hostnames (resueltos una vez, cacheados)
- Comentarios con `#`

El binario refuse-to-start si el archivo no existe (o se arranca con `-no-allowlist` para forzar, dejando warning en stderr).

---

## 9. Implementación por fases

### Fase 1 — Foundation — IMPLEMENTADO
- [x] `internal/poc/` package con tipos y validación (`types.go`)
- [x] `internal/poc/fetch.go` que descarga PoCs de Exploit-DB
- [x] `internal/poc/sandbox_linux.go` con L1 funcional (namespaces + rlimits)
- [x] `internal/poc/sandbox_other.go` stub portable
- [x] `internal/poc/audit.go` con append-only log + HMAC-SHA256
- [x] `internal/poc/classifier.go` con heurística de risk
- [x] `internal/poc/allowlist.go` con CIDR + IPs + hostnames
- [x] `internal/poc/store.go` con PoC persistence + index
- [x] `internal/poc/state.go` bundle compartido
- [x] Tests: `TestSandboxRunHello`, `TestSandbox_IsolatedFS` (via ulimit), `TestClassifier_*`, `TestAllowlist*`, `TestAuditLogTamperDetected`

### Fase 2 — MCP integration — IMPLEMENTADO
- [x] 6 tools nuevas en `internal/mcp/server.go`: `apophis_poc_list`, `apophis_poc_preview`, `apophis_poc_run`, `apophis_poc_history`, `apophis_poc_kill`, `apophis_poc_allowlist`
- [x] Validación de inputs (allow-list, max-risk, confirm, sandbox-level, timeout)
- [x] `apophis_poc_preview` primero (no ejecuta), `apophis_poc_run` después
- [x] `apophis_poc_kill` con cancelación de contexto
- [x] `confirm` validado como bool literal por JSON schema

### Fase 3 — Hardening — IMPLEMENTADO (parcial)
- [x] User-namespace mapping (rootless) en L2 via OCI spec
- [x] Network namespace en L1 (`CLONE_NEWNET` cuando hay capability)
- [x] `NO_NEW_PRIVS`, `oom_score_adj=1000`, capabilities vacías, maskedPaths/readonlyPaths
- [ ] Seccomp BPF program (Phase 1 wrapper usa `ulimit` + `setpriv`; seccomp es un TODO para PR futuro)
- [ ] Network namespace con proxy para target-only (L1 solo aísla, no enruta)
- [ ] Auditor de escape attempts (lsof, strace passivo) — fuera de scope de esta entrega
- [ ] Fuzz del handler MCP — fuera de scope de esta entrega

### Fase 4 — Container sandbox — IMPLEMENTADO
- [x] `internal/poc/runc_sandbox.go` (build linux) — genera OCI 1.0.2 bundle
- [x] `runc_sandbox_other.go` stub para non-Linux
- [x] Validación de `runc` instalado (`exec.LookPath`); auto-degradación a L1 con warning
- [x] Bundle con: namespaces pid/net/ipc/uts/mount, caps vacías, rootfs read-only, maskedPaths (`/proc/asound`, `/proc/acpi`, `/proc/kcore`, `/sys/firmware`, ...), readonlyPaths (`/proc/sys`, `/proc/sysrq-trigger`, ...), rlimits (CPU/NOFILE/NPROC/FSIZE), pids limit, mem/cpu quota, rootless UID/GID mapping
- [x] Timeout con `runc kill SIGKILL` + `runc delete --force`
- [ ] Imagen `apophis/sandbox:stable` con busybox + python3 + nmap bundleada — el operador provee el rootfs; el bundle se construye en runtime desde los assets disponibles

### Fase 5 — Firecracker microVM — STUB EXPLÍCITO
- [x] `internal/poc/firecracker_sandbox.go` con pool de VMs, `Acquire`/`Release`, métricas
- [x] `FCMetrics{BootMs, ExecMs, SnapshotMs, RestoreMs, BootCount, ExecCount, TotalVMPaused}` con moving average
- [x] Detección de binario + check de KVM documentado como TODO
- [x] `BootVM` / `Snapshot` / `Restore` / `Exec` retornan error con `TODO(phase-5)` y ref a §5
- [ ] Pool de VMs pre-booteadas (estructura lista, hot-path no implementado)
- [ ] Snapshot+restore real (API socket PUT /snapshot/create + /snapshot/load)
- [ ] Guest-vsock para I/O (canal de comunicación con el guest)
- [ ] Métricas de overhead reales (los moving averages ya están; los valores son 0 hasta que se implemente el boot real)

### Fase 6 — Integraciones avanzadas — IMPLEMENTADO
- [x] `internal/poc/integrations.go` con:
  - `MSFRPC`: cliente HTTP + msgpack-rpc **hand-rolled** (sin deps) hacia `msfrpcd`. Métodos: `Login()`, `ModuleExecute(type, name, opts)`, `URLValid()`. Codec msgpack soporta nil/bool/uint*/int*/float/string/[]byte/[]any/map[string]any/anidados.
  - `NucleiDispatcher`: spawn de `nuclei -t <tpl> -u <target> -json-export -` con timeout
  - `BoofuzzDispatcher`: spawn de `python3 <script> --target <target>` con timeout
- [x] `resolveDispatcher(src)` mapea `metasploit|msf|msfconsole → msfrpc`, `nuclei → nuclei`, `fuzz|boofuzz → boofuzz`. Otros caen al sandbox estándar.
- [x] `Executor.runInSandboxWith` consulta el dispatcher antes de L1/L2
- [ ] Auto-fuzz con generación automática de scripts Boofuzz (acepta scripts pre-escritos; auto-gen es un TODO)

---

## 10. Tests obligatorios antes de merge

1. **Sandbox escape**: PoC que intenta `mount /proc /proc`, `chroot`, `pivot_root`, escribir en `/proc/sysrq-trigger`. Debe fallar.
2. **Network leak**: PoC que intenta `connect(2)` a `1.1.1.1`. Debe fallar (timeout o `EPERM`).
3. **Resource exhaustion**: fork-bomb (`bash -c ':(){:|:&};:`). El proceso entero muere, host intacto.
4. **Side-channel timing**: medir si L1 filtra info del host. No debería.
5. **Audit log tampering**: editar el log, verificar que el HMAC falla en el siguiente read.
6. **Allow-list bypass**: PoC con `target=8.8.8.8` (no permitido), verificar que se rechaza antes de fork.
7. **`confirm: "true"` (string) vs `confirm: true` (bool)**: el segundo pasa, el primero no.
8. **Concurrent executions**: 5 PoCs en paralelo sobre el mismo target, todos los logs presentes, todos los PIDs únicos.

---

## 11. Lo que el LLM NO debe poder hacer

- Bypass de `confirm: true`.
- Ejecutar PoCs `destructive` sin `max-risk=destructive` al arranque.
- Atacar targets fuera de la allow-list.
- Pasar comandos shell arbitrarios como `args`. Los args se validan contra la lista declarada en el PoC; lo que no esté ahí, se ignora.
- Subir el audit log a internet sin la URL del SIEM pre-configurada.
- Activar el executor en runtime — solo se puede con el flag al arranque.
- Cambiar `execution-timeout` después del arranque (es un flag, no una tool).

---

## 12. Decisiones abiertas (a resolver antes de empezar)

- [ ] **Persistencia de la allow-list**: ¿archivo plano, sqlite, vault?  → recomendación: archivo plano + checksum HMAC.
- [ ] **¿Soporte Windows?** El sandbox L1 no funciona en Windows. ¿WLS2? ¿Hyper-V? → recomendación: deferir a v0.4.
- [ ] **¿PoCs que requieren dependencias externas (libssl-dev, nmap binarios)?** → bundlear imagen Docker con todo, o un resolver que indique "este PoC necesita libfoo, instalalo antes".
- [ ] **¿Cómo manejamos PoCs de "remote code execution en el target" que necesariamente escriben en el target?** Son legítimos. El log los marca como `rce` y exige `confirm: true` por separado.
- [ ] **¿Compartir la DB de ejecuciones entre instancias de Apophis?** → recomendación: no, mantener local; federar via SIEM.
- [ ] **¿Soporte para PoC con credenciales requeridas?** (e.g. `python poc.py --user admin --pass admin`). El handler debe permitir pasar un vault de creds, no hardcodear en el PoC.
- [ ] **Política de retención de logs**: ¿indefinido? ¿30 días? ¿cifrado at-rest?
- [ ] **¿Auto-update del sandbox image?** Si L2, ¿de dónde? ¿firma con cosign?

---

## 13. Riesgos residuales y honestidad

- Cualquier PoC que ejecute código nativo con bugs del kernel del host puede escapar L1.
- El log no impide que un operador malicioso use Apophis para atacar objetivos no autorizados — solo lo dificulta.
- El análisis estático de riesgo (sección 3) puede ser evadido por ofuscación, por eso el sandbox no es opcional.
- L1 con namespaces requiere kernel >= 3.8 y `user_namespaces` no debe estar deshabilitado con `kernel.unprivileged_userns_clone=0` (lo cual Ubuntu 24.04 hace por defecto — hay que documentar).
- En sistemas donde `user_namespaces` no están disponibles, el único aislamiento fuerte es L2 (container). Si L2 no está disponible, **el executor refuse-to-run** y avisa.

Esto es un módulo de **alto riesgo**. Merece un PR review estricto, al menos dos mantenedores, y un changelog que advierta del cambio en la `ethics.md` del repo.

---

## 14. Lectura recomendada antes de implementar

- [Linux namespaces man page](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- [seccomp(2) y libseccomp-golang](https://pkg.go.dev/github.com/seccomp/libseccomp-golang)
- [runc spec](https://github.com/opencontainers/runc/blob/main/man/runc-spec.ko.md)
- [Firecracker design docs](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [gVisor paper](https://www.usenix.org/system/files/osdi19-pasternak.pdf)

---

## 15. Resumen de 30 segundos

APOPHIS v0.2 descubre CVEs. El executor (futuro) los ejecuta contra el target, con:

- allow-list persistente de hosts permitidos
- flag `-enable-executor` off-by-default
- tres niveles de aislamiento (namespaces → container → microVM)
- audit log inmutable con HMAC
- clasificación de riesgo de cada PoC
- `confirm: true` literal en cada invocación
- kill switch y timeouts duros
- cero manera de bypass desde el LLM

Si esto se siente como "mucho" para ejecutar un script de Python: **es mucho a propósito**. El problema que estamos resolviendo es ejecutar código que no escribimos nosotros en máquinas que no son nuestras. El costo de un escape es, literalmente, perder una máquina o una red. El diseño asume eso y se defiende en profundidad.

---

## 16. Cómo se usa (operador)

```bash
# 1. Crear el allowlist (sin él, el binario refuse-to-start con -enable-executor)
cat > ~/.apophis/allowlist.txt <<'EOF'
10.10.10.5
10.10.11.0/24
scanme.nmap.org
EOF

# 2. Arrancar el binario
bin/apophis -enable-executor -max-risk rce -allow-targets ~/.apophis/allowlist.txt

# 3. Desde el LLM (OpenCode), el flujo seguro es siempre 3 pasos:
#    apophis_poc_list     { cve: "CVE-2017-0144" }                    -> id de PoC
#    apophis_poc_preview  { poc_id: "EDB-42315", target: "10.10.10.5" } -> cmd/env/sandbox
#    apophis_poc_run      { poc_id: "EDB-42315", target: "10.10.10.5", confirm: true }
#    apophis_poc_history  { target: "10.10.10.5" }                    -> auditoría
#    apophis_poc_kill     { execution_id: "..." }                       -> kill switch
#    apophis_poc_allowlist { action: "add", target: "10.20.30.40", note: "nuevo lab" }
```

Flags CLI relevantes (todos con `-h` los lista):

| Flag | Default | Significado |
|------|---------|------------|
| `-enable-executor` | `false` | off-by-default, hay que activarlo |
| `-max-risk` | `rce` | `info` \| `safe` \| `rce` \| `destructive` |
| `-allow-container-sandbox` | `false` | habilita L2 (runc) |
| `-executor-user` | `apophis-exec` | uid bajo el que corren los PoCs |
| `-execution-timeout` | `5m` | kill por timeout |
| `-allow-targets` | `~/.apophis/allowlist.txt` | archivo con targets permitidos |
| `-no-allowlist` | `false` | arranca sin allowlist (warning en stderr) |
| `-dry-run-executor` | `false` | todos los PoC se ejecutan en stub (devuelven exit 0) |
| `-msfrpc-url` | — | URL del daemon msfrpcd (Fase 6) |
| `-msfrpc-user` | `msf` | usuario msfrpcd |
| `-msfrpc-pass` | — | password msfrpcd |
| `-nuclei-binary` | `nuclei` | path al binario de nuclei |
| `-nuclei-templates` | — | directorio de templates |
| `-boofuzz-python` | `python3` | intérprete para boofuzz |

## 17. Estado de los tests (42 casos)

```
go test ./internal/poc/... -v
```

Cubre:
- `TestClassifierInfo|Safe|RCE|Destructive|CurlPipeSh` — heurística
- `TestSignatureStable`, `TestParseRisk`
- `TestAllowlistIPExact|CIDR|Hostname|Invalid|FileLoad|ListSorted|Remove`
- `TestAuditLogAppendAndRead|TamperDetected|List`
- `TestExecutorDryRun|Disabled|NotInAllowlist|RiskTooHigh|RequiresConfirm|TimeoutExceedsMax`
- `TestSandboxRunHello` — `/bin/echo` real corre dentro de L1
- `TestRuncOptionsIsInstalled|GenerateBundle|RunNotInstalled|NonLinuxOther` — OCI spec validada con `TestRuncGenerateBundle`
- `TestFirecrackerOptionsIsInstalled|AcquireNotInstalled|SnapshotRestoreStubs|MetricsInitialized|StopAll`
- `TestMSFRPCURLValid|CallInvalidURL`, `TestMsgpackRoundTripPrimitives|EncodeAuthLoginShape|EncodeEmptyMap|EncodeEmptyArray` — codec msgpack con round-trip de 15 tipos
- `TestNucleiIsInstalled|DispatchNotInstalled`
- `TestBoofuzzIsInstalled|DispatchNotInstalled`
- `TestResolveDispatcher|ParseModulePath|SplitKV` — dispatchers

## 18. Estado real vs. diseño

| Pieza del diseño | Estado | Notas |
|------------------|--------|-------|
| L1 subprocess + namespaces | Implementado | `CLONE_NEWNET` solo si hay capability; `NO_NEW_PRIVS`, `oom_score_adj=1000`, rlimits via wrapper `ulimit` |
| L2 runc OCI container | Implementado | spec 1.0.2 con all-caps-dropped, rootless, rootfs read-only; auto-degrada a L1 si runc no está |
| L3 Firecracker microVM | Stub | estructura, pool y métricas listas; API socket / vsock / snapshot es TODO en `firecracker_sandbox.go` |
| Allow-list persistente | Implementado | IPs, CIDR, hostnames (con DNS lookup al matchear); reject si target fuera |
| Audit log inmutable con HMAC | Implementado | append-only, HMAC-SHA256, canonical JSON, tamper detection en read |
| Clasificación de riesgo | Implementado | keywords con evaluación ordenada (destructive > rce > safe > info) |
| `confirm: true` literal | Implementado | JSON schema rechaza string `"true"`; sentinel `ErrMissingConfirm` |
| Kill switch | Implementado | `apophis_poc_kill` con cancelación de contexto |
| Timeouts duros | Implementado | `execution-timeout` global + `timeout_sec` por invocación |
| Metasploit RPC | Implementado | cliente msgpack-rpc hand-rolled; dispatch automático cuando `PoC.Source = "metasploit"` |
| Nuclei executor | Implementado | dispatch automático cuando `PoC.Source = "nuclei"` |
| Boofuzz dispatcher | Implementado (parcial) | dispatch automático cuando `PoC.Source = "fuzz"`; auto-generación de scripts es TODO |
| Seccomp BPF estricto | Pendiente | PR futuro; L1 usa `ulimit`+`setpriv` como primera barrera |
| Network proxy target-only | Pendiente | L1 solo aísla, no enruta por target específico |
| Imagen `apophis/sandbox:stable` | Parcial | el bundle se construye en runtime desde el rootfs del operador; no bundleamos busybox/python/nmap |
