//go:build !linux

package poc

import (
	"context"
	"errors"
	"os/exec"
	"syscall"
	"time"
)

type RLimits struct {
	CPUSeconds   int64
	AddressBytes int64
	FileSize     int64
	NProc        int64
	NOFile       int64
}

func DefaultRLimits() RLimits {
	return RLimits{CPUSeconds: 60, AddressBytes: 512 * 1024 * 1024, FileSize: 64 * 1024 * 1024, NProc: 32, NOFile: 64}
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

type L1Sandbox struct{ opts L1Options }

func NewL1Sandbox(opts L1Options) *L1Sandbox {
	if opts.RLimits.CPUSeconds == 0 {
		opts.RLimits = DefaultRLimits()
	}
	return &L1Sandbox{opts: opts}
}

func Capabilities() (namespaces, noNewPrivs, dropCaps bool) { return false, false, false }

func (s *L1Sandbox) Run(ctx context.Context, argv0 string, args []string, workdir string) (*RunResult, error) {
	if len(args) == 0 {
		args = []string{argv0}
	}
	cmd := exec.Command(argv0, args[1:]...)
	cmd.Dir = workdir
	cmd.Env = s.opts.ExtraEnv
	started := time.Now()
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timeout := time.Duration(s.opts.RLimits.CPUSeconds+5) * time.Second
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
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
			Error:      "execution exceeded timeout",
		}, nil
	case err := <-done:
		finished := time.Now()
		res := &RunResult{StartedAt: started, FinishedAt: finished, DurationMs: finished.Sub(started).Milliseconds()}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			res.ExitCode = exitErr.ExitCode()
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				res.Signal = status.Signal().String()
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
