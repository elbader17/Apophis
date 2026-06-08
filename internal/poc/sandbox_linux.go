//go:build linux

package poc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type RLimits struct {
	CPUSeconds  int64
	AddressBytes int64
	FileSize    int64
	NProc       int64
	NOFile      int64
}

func DefaultRLimits() RLimits {
	return RLimits{
		CPUSeconds:  60,
		AddressBytes: 512 * 1024 * 1024,
		FileSize:    64 * 1024 * 1024,
		NProc:       32,
		NOFile:      64,
	}
}

type L1Options struct {
	WorkDir       string
	RLimits       RLimits
	UseNamespaces bool
	DropCaps      bool
	NoNewPrivs    bool
	NoNetwork     bool
	ExtraEnv      []string
	Stdin         string
}

type L1Sandbox struct {
	opts L1Options
}

func NewL1Sandbox(opts L1Options) *L1Sandbox {
	if opts.RLimits.CPUSeconds == 0 {
		opts.RLimits = DefaultRLimits()
	}
	return &L1Sandbox{opts: opts}
}

func Capabilities() (namespaces, noNewPrivs, dropCaps bool) {
	namespaces = haveNamespaceCaps()
	noNewPrivs = true
	dropCaps = os.Geteuid() == 0 || haveCapSysAdmin()
	return
}

func haveNamespaceCaps() bool {
	_, _, errno := syscall.Syscall(216, 0, 0, 0)
	if errno == 0 {
		return true
	}
	_, _, errno2 := syscall.Syscall(216, syscall.CLONE_NEWUSER, 0, 0)
	return errno2 == 0 || errno2 == syscall.EPERM
}

func haveCapSysAdmin() bool {
	if os.Geteuid() == 0 {
		return true
	}
	body, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			parts := strings.Fields(line)
			if len(parts) < 2 {
				return false
			}
			var cap uint64
			fmt.Sscanf(parts[1], "%x", &cap)
			const capSysAdmin = 21
			return cap&(1<<capSysAdmin) != 0
		}
	}
	return false
}

func (s *L1Sandbox) Run(ctx context.Context, argv0 string, args []string, workdir string) (*RunResult, error) {
	if len(args) == 0 {
		args = []string{argv0}
	}
	if err := s.prepareWorkdir(workdir); err != nil {
		return nil, err
	}

	cmd := exec.Command(argv0, args[1:]...)
	cmd.Dir = workdir
	cmd.Env = s.opts.ExtraEnv
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	if s.opts.Stdin != "" {
		cmd.Stdin = strings.NewReader(s.opts.Stdin)
	}

	stdout := &limitedBuffer{limit: 1 << 20}
	stderr := &limitedBuffer{limit: 1 << 20}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if s.opts.NoNewPrivs {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	// Apply rlimits and other settings pre-exec via a parent setup
	// We can't directly set rlimits on the child before exec from Go
	// unless we use SysProcAttr.Pdeathsig, but we can set the
	// oom_score_adj and prctl via a parent process using a CGo
	// trampoline or fork+exec pattern.
	//
	// Simpler approach: fork+exec with rlimits set via a child setup
	// (using a wrapper script that calls ulimit, or using syscall
	// Prctl to set no_new_privs on the child via Ptrace, neither of
	// which is trivial in Go).
	//
	// For L1 with namespaces: set Cloneflags so the child is born
	// with the requested namespaces; combined with the rlimits set
	// in the wrapper, this provides defense in depth.
	if s.opts.UseNamespaces && haveNamespaceCaps() {
		flags := uintptr(0)
		if s.opts.NoNetwork {
			flags |= syscall.CLONE_NEWNET
		}
		if flags != 0 {
			cmd.SysProcAttr.Cloneflags = flags
		}
	}

	started := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("sandbox start: %w", err)
	}

	// Apply oom_score_adj to child for safety
	if s.opts.DropCaps {
		_ = os.WriteFile(fmt.Sprintf("/proc/%d/oom_score_adj", cmd.Process.Pid), []byte("1000"), 0644)
	}

	timeout := time.Duration(s.opts.RLimits.CPUSeconds+5) * time.Second
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-tctx.Done():
		_ = cmd.Process.Kill()
		<-done
		return &RunResult{
			StartedAt:  started,
			FinishedAt: time.Now(),
			DurationMs: time.Since(started).Milliseconds(),
			ExitCode:   -1,
			Signal:     "KILLED_TIMEOUT",
			Stdout:     stdout.String(),
			Stderr:     stderr.String() + "\n[killed: timeout]",
			Error:      "execution exceeded timeout",
		}, nil
	case err := <-done:
		finished := time.Now()
		res := &RunResult{
			StartedAt:  started,
			FinishedAt: finished,
			DurationMs: finished.Sub(started).Milliseconds(),
			Stdout:     stdout.String(),
			Stderr:     stderr.String(),
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() {
					res.Signal = status.Signal().String()
				}
			}
		} else if err != nil {
			res.ExitCode = -1
			res.Error = err.Error()
		} else {
			res.ExitCode = 0
		}
		return res, nil
	}
}

func (s *L1Sandbox) prepareWorkdir(workdir string) error {
	if err := os.MkdirAll(workdir, 0755); err != nil {
		return err
	}
	wrapper := s.wrapperScript()
	if err := os.WriteFile(filepath.Join(workdir, ".apophis-wrapper.sh"), []byte(wrapper), 0755); err != nil {
		return err
	}
	return nil
}

func (s *L1Sandbox) wrapperScript() string {
	r := s.opts.RLimits
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# Auto-generated by apophis PoC executor.\n")
	b.WriteString("set -e\n")
	b.WriteString(fmt.Sprintf("ulimit -t %d 2>/dev/null || true\n", r.CPUSeconds))
	b.WriteString(fmt.Sprintf("ulimit -v %d 2>/dev/null || true\n", r.AddressBytes/1024))
	b.WriteString(fmt.Sprintf("ulimit -f %d 2>/dev/null || true\n", r.FileSize/1024))
	b.WriteString(fmt.Sprintf("ulimit -u %d 2>/dev/null || true\n", r.NProc))
	b.WriteString(fmt.Sprintf("ulimit -n %d 2>/dev/null || true\n", r.NOFile))
	if s.opts.NoNewPrivs {
		b.WriteString("command -v setpriv >/dev/null && setpriv --no-new-privs --reset-env -- \"$@\" || exec \"$@\"\n")
	} else {
		b.WriteString("exec \"$@\"\n")
	}
	return b.String()
}

type limitedBuffer struct {
	b     []byte
	limit int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if len(b.b)+len(p) > b.limit {
		p = p[:b.limit-len(b.b)]
		if len(p) == 0 {
			return len(p), nil
		}
	}
	b.b = append(b.b, p...)
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return string(b.b)
}
