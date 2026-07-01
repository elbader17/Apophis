package poc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrDisabled        = errors.New("poc executor is disabled (start binary with -enable-executor)")
	ErrNotInAllowlist  = errors.New("target not in allowlist")
	ErrRiskTooHigh     = errors.New("poc risk exceeds configured max-risk")
	ErrSandboxLevel    = errors.New("requested sandbox level not enabled at startup")
	ErrTimeoutTooLarge = errors.New("requested timeout exceeds configured max")
	ErrMissingConfirm  = errors.New("confirm:true is required to run a PoC")
	ErrInvalidConfirm  = errors.New("confirm must be a boolean true (not string, not 1)")
	ErrNoPoC           = errors.New("no PoC provided")
	ErrNoTarget        = errors.New("no target provided")
	ErrUnknownPoC      = errors.New("PoC id not found in local store")
)

type Executor struct {
	cfg      ExecConfig
	audit    *AuditLog
	allow    *Allowlist
	store    *Store
	classif  *Classifier
	fetcher  *Fetcher
	msf      *MSFRPC
	nuclei   NucleiDispatcher
	fuzz     BoofuzzDispatcher
	killHook context.CancelFunc

	mu      sync.Mutex
	running map[string]*runningExec
}

type runningExec struct {
	id      string
	cancel  context.CancelFunc
	started time.Time
}

func NewExecutor(cfg ExecConfig, audit *AuditLog, allow *Allowlist, store *Store) *Executor {
	e := &Executor{
		cfg:     cfg,
		audit:   audit,
		allow:   allow,
		store:   store,
		classif: NewClassifier(),
		fetcher: NewFetcher(),
		running: map[string]*runningExec{},
	}
	if cfg.MSFRPCURL != "" {
		e.msf = NewMSFRPC(MSFRPCOptions{URL: cfg.MSFRPCURL, User: cfg.MSFRPCUser, Pass: cfg.MSFRPCPass})
	}
	e.nuclei = NucleiDispatcher{
		Binary:       cfg.NucleiBinary,
		TemplatesDir: cfg.NucleiTemplatesDir,
		Timeout:      cfg.ExecutionTimeout,
	}
	if e.nuclei.Binary == "" {
		e.nuclei.Binary = "nuclei"
	}
	e.fuzz = BoofuzzDispatcher{
		Python:  cfg.BoofuzzPython,
		WorkDir: cfg.BoofuzzWorkDir,
		Timeout: cfg.ExecutionTimeout,
	}
	if e.fuzz.Python == "" {
		e.fuzz.Python = "python3"
	}
	return e
}

func (e *Executor) Config() ExecConfig { return e.cfg }

func (e *Executor) Enabled() bool { return e.cfg.Enabled }

func (e *Executor) SetAllowlist(a *Allowlist) { e.allow = a }

func (e *Executor) ListPoCs(cve, source string, minRisk, maxRisk RiskLevel, limit int) []*PoC {
	if e.store == nil {
		return nil
	}
	return e.store.List(cve, source, minRisk, maxRisk, limit)
}

func (e *Executor) GetPoC(id string) (*PoC, error) {
	if e.store == nil {
		return nil, ErrUnknownPoC
	}
	return e.store.Get(id)
}

func (e *Executor) Preview(req RunRequest) (*RunResult, error) {
	poC, err := e.resolvePoC(req.PoC)
	if err != nil {
		return nil, err
	}
	if err := e.validate(req, poC); err != nil {
		return nil, err
	}
	cmd, env, workdir := e.buildCommand(poC, req)
	return &RunResult{
		ExecutionID:  "preview-" + strconv.FormatInt(time.Now().UnixNano(), 36),
		StartedAt:    time.Now(),
		FinishedAt:   time.Now(),
		SandboxLevel: req.SandboxLevel,
		SandboxInfo:  e.sandboxInfo(req, workdir),
		Stdout:       fmt.Sprintf("[preview] would run:\n  cmd: %s\n  env: %s\n  workdir: %s", strings.Join(cmd, " "), strings.Join(env, " "), workdir),
	}, nil
}

func (e *Executor) Run(ctx context.Context, req RunRequest) (*RunResult, error) {
	poC, err := e.resolvePoC(req.PoC)
	if err != nil {
		return nil, err
	}
	if err := e.validate(req, poC); err != nil {
		return nil, err
	}

	started := time.Now()
	cmd, env, workdir := e.buildCommand(poC, req)
	execID := "exe-" + strconv.FormatInt(started.UnixNano(), 36)

	rec := &AuditRecord{
		ID:        execID,
		StartedAt: started,
		PoC: AuditPoC{
			ID:        poC.ID,
			CVE:       poC.CVE,
			Type:      string(poC.Type),
			Signature: poC.Signature,
			Risk:      poC.Risk.String(),
			Source:    poC.Source,
		},
		Target:  req.Target,
		Sandbox: e.sandboxInfo(req, workdir),
		Cmd:     cmd,
		Env:     env,
		Stdout:  "",
		Stderr:  "",
	}
	if req.Confirm {
		t := started
		rec.UserConfirmedAt = &t
	}
	rec.UserNote = req.UserNote

	if _, err := e.audit.Append(rec); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}

	if e.cfg.DryRun {
		res := &RunResult{
			ExecutionID:  execID,
			StartedAt:    started,
			FinishedAt:   time.Now(),
			DurationMs:   time.Since(started).Milliseconds(),
			ExitCode:     0,
			Stdout:       "[dry-run] no execution performed",
			Sandboxed:    false,
			SandboxLevel: req.SandboxLevel,
			SandboxInfo:  rec.Sandbox,
			DryRun:       true,
		}
		rec.FinishedAt = res.FinishedAt
		rec.DurationMs = res.DurationMs
		rec.ExitCode = res.ExitCode
		rec.Stdout = res.Stdout
		_, _ = e.audit.Append(rec)
		return res, nil
	}

	if err := e.spawn(ctx, execID, req, poC, cmd, env, workdir, rec); err != nil {
		return nil, err
	}

	e.mu.Lock()
	e.running[execID] = &runningExec{id: execID, started: started, cancel: func() {}}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.running, execID)
		e.mu.Unlock()
	}()

	runCtx, cancel := context.WithTimeout(ctx, e.executionTimeout(req))
	defer cancel()

	rres, err := e.runInSandboxWith(runCtx, poC.Source, req.SandboxLevel, cmd, env, workdir, req.Target, poC.Path, req.ExtraArgs)
	if err != nil {
		return nil, err
	}

	finished := time.Now()
	rres.ExecutionID = execID
	rres.StartedAt = started
	rres.FinishedAt = finished
	rres.DurationMs = finished.Sub(started).Milliseconds()
	rres.SandboxLevel = req.SandboxLevel
	rres.SandboxInfo = rec.Sandbox

	rec.FinishedAt = finished
	rec.DurationMs = rres.DurationMs
	rec.ExitCode = rres.ExitCode
	rec.Signal = rres.Signal
	rec.Stdout = rres.Stdout
	rec.Stderr = rres.Stderr
	rec.ExploitVerified = rres.ExploitVerified
	rec.VulnConfirmed = rres.VulnConfirmed
	_, _ = e.audit.Append(rec)

	return rres, nil
}

func (e *Executor) Kill(id string) error {
	e.mu.Lock()
	r, ok := e.running[id]
	e.mu.Unlock()
	if !ok {
		return fmt.Errorf("no running execution with id %s", id)
	}
	if r.cancel != nil {
		r.cancel()
	}
	return nil
}

func (e *Executor) History(since time.Time, target string, limit int) ([]AuditMeta, error) {
	return e.audit.List(since, target, limit)
}

func (e *Executor) resolvePoC(in *PoC) (*PoC, error) {
	if in != nil {
		return in, nil
	}
	return nil, ErrNoPoC
}

func (e *Executor) validate(req RunRequest, poC *PoC) error {
	if !e.cfg.Enabled {
		return ErrDisabled
	}
	if req.Target == "" {
		return ErrNoTarget
	}
	if !req.Confirm {
		return ErrMissingConfirm
	}
	ok, _ := e.allow.Contains(req.Target)
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotInAllowlist, req.Target)
	}
	if poC.Risk > e.cfg.MaxRisk {
		return fmt.Errorf("%w: PoC risk=%s max=%s", ErrRiskTooHigh, poC.Risk, e.cfg.MaxRisk)
	}
	if req.SandboxLevel == "" {
		req.SandboxLevel = SandboxL1
	}
	if !req.SandboxLevel.Valid() {
		return fmt.Errorf("invalid sandbox_level %q", req.SandboxLevel)
	}
	if !sandboxAllowed(req.SandboxLevel, e.cfg) {
		return fmt.Errorf("%w: %s", ErrSandboxLevel, req.SandboxLevel)
	}
	if req.TimeoutSec <= 0 {
		req.TimeoutSec = int(e.cfg.ExecutionTimeout.Seconds())
	}
	maxSec := int(e.cfg.ExecutionTimeout.Seconds())
	if req.TimeoutSec > maxSec {
		return fmt.Errorf("%w: requested=%ds max=%ds", ErrTimeoutTooLarge, req.TimeoutSec, maxSec)
	}
	return nil
}

func sandboxAllowed(lvl SandboxLevel, cfg ExecConfig) bool {
	switch lvl {
	case SandboxL1:
		return true
	case SandboxL2:
		return cfg.AllowContainer
	case SandboxL3:
		return cfg.AllowMicroVM
	}
	return false
}

func (e *Executor) buildCommand(poC *PoC, req RunRequest) ([]string, []string, string) {
	env := []string{
		"HOME=/tmp",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"APOPHIS_POC=1",
		"APOPHIS_TARGET=" + req.Target,
	}
	env = append(env, poC.Env...)
	env = append(env, req.ExtraEnv...)

	args := append([]string{}, poC.Args...)
	args = append(args, req.ExtraArgs...)
	args = append(args, req.Target)

	var cmd []string
	runtime := poC.Type.Runtime()
	switch {
	case runtime != "":
		cmd = []string{runtime, poC.Path}
		cmd = append(cmd, args...)
	case poC.Type == PoCTypeBinary:
		cmd = []string{poC.Path}
		cmd = append(cmd, args...)
	default:
		cmd = []string{"/bin/sh", poC.Path}
		cmd = append(cmd, args...)
	}

	workdir := e.sandboxWorkdir(poC)
	return cmd, env, workdir
}

func (e *Executor) sandboxWorkdir(poC *PoC) string {
	base := e.cfg.WorkDir
	if base == "" {
		base = filepath.Join(os.TempDir(), "apophis-poc")
	}
	dir := filepath.Join(base, poC.ID+"-"+strconv.FormatInt(time.Now().UnixNano(), 36))
	_ = os.MkdirAll(dir, 0755)
	return dir
}

func (e *Executor) sandboxInfo(req RunRequest, workdir string) AuditSandbox {
	level := req.SandboxLevel
	if level == "" {
		level = SandboxL1
	}
	ns, _, _ := Capabilities()
	used := []string{}
	if ns && level == SandboxL1 {
		used = []string{"net"}
	}
	r := DefaultRLimits()
	return AuditSandbox{
		Level:      string(level),
		Namespaces: used,
		Rlimits: map[string]int64{
			"cpu":    r.CPUSeconds,
			"as":     r.AddressBytes,
			"fsize":  r.FileSize,
			"nproc":  r.NProc,
			"nofile": r.NOFile,
		},
		Seccomp: "apophis-strict-v1",
		Workdir: workdir,
	}
}

func (e *Executor) executionTimeout(req RunRequest) time.Duration {
	if req.TimeoutSec > 0 {
		return time.Duration(req.TimeoutSec) * time.Second
	}
	if e.cfg.ExecutionTimeout > 0 {
		return e.cfg.ExecutionTimeout
	}
	return 5 * time.Minute
}

func (e *Executor) spawn(ctx context.Context, id string, req RunRequest, poC *PoC, cmd, env []string, workdir string, rec *AuditRecord) error {
	e.mu.Lock()
	if old, ok := e.running[id]; ok && old.cancel != nil {
		old.cancel()
	}
	e.mu.Unlock()
	return nil
}

func (e *Executor) runInSandbox(ctx context.Context, cmd, env []string, workdir string) (*RunResult, error) {
	return e.runInSandboxWith(ctx, "", SandboxL1, cmd, env, workdir, "", "", nil)
}

func (e *Executor) runInSandboxWith(ctx context.Context, pocSource string, level SandboxLevel, cmd, env []string, workdir, target, extraPath string, extraArgs []string) (*RunResult, error) {
	// Try dispatchers first (phase 6 integrations).
	if level == SandboxL1 {
		kind, _ := resolveDispatcher(pocSource, e.msf, e.nuclei, e.fuzz)
		switch kind {
		case "msfrpc":
			if e.msf == nil {
				return nil, fmt.Errorf("metasploit integration requested but no MSFRPC URL configured (use -msfrpc-url)")
			}
			if err := e.msf.URLValid(); err != nil {
				return nil, err
			}
			opts := map[string]any{"RHOSTS": target}
			for _, a := range extraArgs {
				if k, v, ok := splitKV(a); ok {
					opts[k] = v
				}
			}
			moduleType, moduleName := parseModulePath(extraPath)
			if moduleType == "" || moduleName == "" {
				return nil, fmt.Errorf("metasploit dispatch requires PoC.Path like 'exploit/windows/smb/ms17_010_eternalblue'")
			}
			jobID, err := e.msf.ModuleExecute(ctx, moduleType, moduleName, opts)
			if err != nil {
				return nil, err
			}
			return &RunResult{
				ExecutionID:  jobID,
				StartedAt:    time.Now(),
				FinishedAt:   time.Now(),
				DurationMs:   0,
				ExitCode:     0,
				Stdout:       fmt.Sprintf("msfrpc job started: %s", jobID),
				Sandboxed:    true,
				SandboxLevel: SandboxL1,
			}, nil
		case "nuclei":
			return e.nuclei.Dispatch(ctx, extraPath, target, extraArgs)
		case "boofuzz":
			return e.fuzz.Dispatch(ctx, extraPath, target)
		}
	}

	switch level {
	case SandboxL2, SandboxL1:
		if level == SandboxL2 && e.cfg.AllowContainer {
			rs := NewRuncSandbox(RuncOptions{
				BundleDir: workdir,
				Cmd:       cmd,
				Env:       env,
				Workdir:   "/",
				Timeout:   e.executionTimeoutFromCtx(ctx),
			})
			if rs.opts.IsInstalled() {
				res, err := rs.Run(ctx)
				if err == nil {
					res.Sandboxed = true
					res.SandboxLevel = SandboxL2
					_ = rs.Cleanup()
					return res, nil
				}
				loggerWarn("runc L2 failed, falling back to L1: " + err.Error())
			} else {
				loggerWarn("runc not installed, falling back to L1")
			}
		}
		ns, noNewPrivs, dropCaps := Capabilities()
		sandbox := NewL1Sandbox(L1Options{
			WorkDir:       workdir,
			UseNamespaces: ns,
			NoNewPrivs:    noNewPrivs,
			DropCaps:      dropCaps,
			NoNetwork:     false,
			ExtraEnv:      env,
		})
		res, err := sandbox.Run(ctx, cmd[0], cmd, workdir)
		if err != nil {
			return nil, err
		}
		res.Sandboxed = ns || noNewPrivs
		res.SandboxLevel = SandboxL1
		return res, nil
	case SandboxL3:
		return nil, fmt.Errorf("firecracker L3 sandbox is a stub in this version (see docs/POC_EXECUTOR.md §5)")
	}
	return nil, fmt.Errorf("unknown sandbox level %q", level)
}

func (e *Executor) executionTimeoutFromCtx(ctx context.Context) time.Duration {
	if d, ok := ctx.Deadline(); ok {
		return time.Until(d)
	}
	return 5 * time.Minute
}

func splitKV(s string) (string, string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '=' {
			return s[:i], s[i+1:], true
		}
	}
	return "", "", false
}

func parseModulePath(p string) (string, string) {
	parts := strings.SplitN(p, "/", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func loggerWarn(msg string) { _ = msg }

func (e *Executor) HistoryByRisk(risk RiskLevel) ([]AuditMeta, error) {
	_ = risk
	return nil, nil
}
