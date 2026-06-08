//go:build !linux

package poc

import (
	"context"
	"fmt"
	"time"
)

type RuncOptions struct {
	BundleDir    string
	RuncBinary   string
	ContainerID  string
	RootfsPath   string
	Cmd          []string
	Env          []string
	Workdir      string
	MemoryLimit  int64
	CPULimitSec  int64
	PidsLimit    int64
	NoNewPrivs   bool
	UserNSMap    bool
	ReadOnlyRoot bool
	Timeout      time.Duration
}

func DefaultRuncOptions() RuncOptions {
	return RuncOptions{
		RuncBinary:   "runc",
		ContainerID:  "apophis-poc",
		MemoryLimit:  512 * 1024 * 1024,
		CPULimitSec:  60,
		PidsLimit:    32,
		NoNewPrivs:   true,
		UserNSMap:    true,
		ReadOnlyRoot: true,
		Timeout:      5 * time.Minute,
	}
}

func (o RuncOptions) IsInstalled() bool { return false }

type RuncSandbox struct{ opts RuncOptions }

func NewRuncSandbox(opts RuncOptions) *RuncSandbox {
	return &RuncSandbox{opts: opts}
}

func (s *RuncSandbox) GenerateBundle() error {
	return fmt.Errorf("runc sandbox is only supported on Linux")
}

func (s *RuncSandbox) Run(ctx context.Context) (*RunResult, error) {
	return nil, fmt.Errorf("runc sandbox is only supported on Linux")
}

func (s *RuncSandbox) Cleanup() error { return nil }
