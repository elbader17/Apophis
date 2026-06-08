//go:build linux

package poc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
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
	UserNSMap   bool
	ReadOnlyRoot bool
	Timeout      time.Duration
}

type RuncSandbox struct {
	opts RuncOptions
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

func (o RuncOptions) IsInstalled() bool {
	bin := o.RuncBinary
	if bin == "" {
		bin = "runc"
	}
	_, err := exec.LookPath(bin)
	return err == nil
}

func NewRuncSandbox(opts RuncOptions) *RuncSandbox {
	if opts.RuncBinary == "" {
		opts.RuncBinary = "runc"
	}
	if opts.ContainerID == "" {
		opts.ContainerID = "apophis-poc-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	}
	if opts.MemoryLimit == 0 {
		opts.MemoryLimit = 512 * 1024 * 1024
	}
	if opts.CPULimitSec == 0 {
		opts.CPULimitSec = 60
	}
	if opts.PidsLimit == 0 {
		opts.PidsLimit = 32
	}
	return &RuncSandbox{opts: opts}
}

type runcSpec struct {
	OCIVersion string         `json:"ociVersion"`
	Process    *runcProcess   `json:"process,omitempty"`
	Root       *runcRoot      `json:"root"`
	Hostname   string         `json:"hostname,omitempty"`
	Mounts     []runcMount    `json:"mounts,omitempty"`
	Linux      *runcLinux     `json:"linux"`
}

type runcProcess struct {
	User           runcUser     `json:"user"`
	Args           []string     `json:"args"`
	Env            []string     `json:"env"`
	Cwd            string       `json:"cwd"`
	NoNewPrivileges bool        `json:"noNewPrivileges"`
	Capabilities    runcCaps    `json:"capabilities"`
}

type runcUser struct {
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	AdditionalGids []uint32 `json:"additionalGids,omitempty"`
	Username       string  `json:"username,omitempty"`
}

type runcCaps struct {
	Bounding     []string `json:"bounding"`
	Effective    []string `json:"effective"`
	Permitted    []string `json:"permitted"`
	Inheritable  []string `json:"inheritable"`
	Ambient      []string `json:"ambient"`
}

type runcRoot struct {
	Path     string `json:"path"`
	Readonly bool   `json:"readonly,omitempty"`
}

type runcMount struct {
	Destination string   `json:"destination"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	Options     []string `json:"options,omitempty"`
}

type runcLinux struct {
	Namespaces    []runcNamespace `json:"namespaces"`
	Resources     *runcResources  `json:"resources,omitempty"`
	UIDMappings   []runcIDMap     `json:"uidMappings,omitempty"`
	GIDMappings   []runcIDMap     `json:"gidMappings,omitempty"`
	MaskedPaths   []string        `json:"maskedPaths,omitempty"`
	ReadonlyPaths []string        `json:"readonlyPaths,omitempty"`
	Rootless      bool            `json:"rootless,omitempty"`
}

type runcNamespace struct {
	Type string `json:"type"`
	Path string `json:"path,omitempty"`
}

type runcResources struct {
	Memory  *runcMemory `json:"memory,omitempty"`
	CPU     *runcCPU    `json:"cpu,omitempty"`
	Pids    *runcPids   `json:"pids,omitempty"`
	Rlimits []runcRLim  `json:"rlimits,omitempty"`
}

type runcMemory struct {
	Limit       *int64 `json:"limit,omitempty"`
	Reservation *int64 `json:"reservation,omitempty"`
	Swap        *int64 `json:"swap,omitempty"`
}

type runcCPU struct {
	Quota  *int64 `json:"quota,omitempty"`
	Period *int64 `json:"period,omitempty"`
}

type runcPids struct {
	Limit int64 `json:"limit"`
}

type runcRLim struct {
	Type string `json:"type"`
	Soft uint64 `json:"soft"`
	Hard uint64 `json:"hard"`
}

type runcIDMap struct {
	ContainerID int    `json:"containerID"`
	HostID      int    `json:"hostID"`
	Size        int    `json:"size"`
}

func defaultMaskedPaths() []string {
	return []string{
		"/proc/asound", "/proc/acpi", "/proc/kcore", "/proc/keys",
		"/proc/latency_stats", "/proc/timer_list", "/proc/timer_stats",
		"/proc/sched_debug", "/proc/scsi", "/sys/firmware",
		"/sys/devices/virtual/powercap",
	}
}

func defaultReadonlyPaths() []string {
	return []string{
		"/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq",
		"/proc/sys", "/proc/sysrq-trigger",
	}
}

func (s *RuncSandbox) GenerateBundle() error {
	if s.opts.BundleDir == "" {
		return fmt.Errorf("bundle dir is required")
	}
	if err := os.MkdirAll(s.opts.BundleDir, 0755); err != nil {
		return err
	}
	rootfs := filepath.Join(s.opts.BundleDir, "rootfs")
	if s.opts.RootfsPath != "" {
		rootfs = s.opts.RootfsPath
	}
	if err := os.MkdirAll(filepath.Join(rootfs, "tmp"), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(rootfs, "poc"), 0755); err != nil {
		return err
	}
	for _, src := range s.opts.Cmd[1:] {
		if _, err := os.Stat(src); err == nil {
			dst := filepath.Join(rootfs, "poc", filepath.Base(src))
			if err := copyFile(src, dst); err != nil {
				return err
			}
		}
	}

	quota := s.opts.CPULimitSec * 1000
	period := int64(100000)
	memLimit := s.opts.MemoryLimit

	spec := runcSpec{
		OCIVersion: "1.0.2",
		Process: &runcProcess{
			User:            runcUser{UID: 65534, GID: 65534},
			Args:            s.opts.Cmd,
			Env:             s.opts.Env,
			Cwd:             s.opts.Workdir,
			NoNewPrivileges: s.opts.NoNewPrivs,
			Capabilities: runcCaps{
				Bounding:    []string{},
				Effective:   []string{},
				Permitted:   []string{},
				Inheritable: []string{},
			},
		},
		Root: &runcRoot{
			Path:     "rootfs",
			Readonly: s.opts.ReadOnlyRoot,
		},
		Hostname: "apophis-poc",
		Mounts: []runcMount{
			{Destination: "/proc", Type: "proc", Source: "proc"},
			{Destination: "/dev", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "strictatime", "mode=755", "size=65536k"}},
			{Destination: "/dev/pts", Type: "devpts", Source: "devpts", Options: []string{"nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"}},
			{Destination: "/dev/shm", Type: "tmpfs", Source: "shm", Options: []string{"nosuid", "nodev", "noexec", "mode=1777", "size=65536k"}},
			{Destination: "/tmp", Type: "tmpfs", Source: "tmpfs", Options: []string{"nosuid", "nodev", "noexec", "mode=1777", "size=65536k"}},
			{Destination: "/sys", Type: "none", Source: "/sys", Options: []string{"nosuid", "noexec", "nodev", "ro", "bind"}},
		},
		Linux: &runcLinux{
			Namespaces: []runcNamespace{
				{Type: "pid"},
				{Type: "network"},
				{Type: "ipc"},
				{Type: "uts"},
				{Type: "mount"},
			},
			Resources: &runcResources{
				Memory: &runcMemory{Limit: &memLimit},
				CPU:    &runcCPU{Quota: &quota, Period: &period},
				Pids:   &runcPids{Limit: s.opts.PidsLimit},
				Rlimits: []runcRLim{
					{Type: "RLIMIT_CPU", Soft: uint64(s.opts.CPULimitSec), Hard: uint64(s.opts.CPULimitSec)},
					{Type: "RLIMIT_NOFILE", Soft: 64, Hard: 64},
					{Type: "RLIMIT_NPROC", Soft: uint64(s.opts.PidsLimit), Hard: uint64(s.opts.PidsLimit)},
					{Type: "RLIMIT_FSIZE", Soft: 64 * 1024 * 1024, Hard: 64 * 1024 * 1024},
				},
			},
			MaskedPaths:   defaultMaskedPaths(),
			ReadonlyPaths: defaultReadonlyPaths(),
		},
	}
	if s.opts.UserNSMap {
		spec.Linux.UIDMappings = []runcIDMap{{ContainerID: 0, HostID: 65534, Size: 1}}
		spec.Linux.GIDMappings = []runcIDMap{{ContainerID: 0, HostID: 65534, Size: 1}}
		spec.Linux.Rootless = true
	}

	cfgPath := filepath.Join(s.opts.BundleDir, "config.json")
	b, err := json.MarshalIndent(spec, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(cfgPath, b, 0644)
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

func (s *RuncSandbox) Run(ctx context.Context) (*RunResult, error) {
	if !s.opts.IsInstalled() {
		return nil, fmt.Errorf("runc binary %q not found in PATH; install runc or downgrade to L1", s.opts.RuncBinary)
	}
	if err := s.GenerateBundle(); err != nil {
		return nil, fmt.Errorf("generate bundle: %w", err)
	}

	started := time.Now()
	stdout := &limitedBuffer{limit: 1 << 20}
	stderr := &limitedBuffer{limit: 1 << 20}

	cmd := exec.CommandContext(ctx, s.opts.RuncBinary, "--bundle", s.opts.BundleDir, "run", s.opts.ContainerID)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("runc start: %w", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case <-ctx.Done():
		_ = cmd.Process.Kill()
		_ = exec.Command(s.opts.RuncBinary, "kill", s.opts.ContainerID, "SIGKILL").Run()
		<-done
		_ = exec.Command(s.opts.RuncBinary, "delete", "--force", s.opts.ContainerID).Run()
		return &RunResult{
			StartedAt:  started,
			FinishedAt: time.Now(),
			DurationMs: time.Since(started).Milliseconds(),
			ExitCode:   -1,
			Signal:     "KILLED_TIMEOUT",
			Stdout:     stdout.String(),
			Stderr:     stderr.String() + "\n[killed: timeout]",
			Error:      "runc execution exceeded timeout",
		}, nil
	case err := <-done:
		_ = exec.Command(s.opts.RuncBinary, "delete", "--force", s.opts.ContainerID).Run()
		finished := time.Now()
		res := &RunResult{
			StartedAt:  started,
			FinishedAt: finished,
			DurationMs: finished.Sub(started).Milliseconds(),
			Stdout:     stdout.String(),
			Stderr:     stderr.String(),
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			res.ExitCode = exitErr.ExitCode()
		} else if err != nil {
			res.Error = err.Error()
		} else {
			res.ExitCode = 0
		}
		return res, nil
	}
}

func (s *RuncSandbox) Cleanup() error {
	if !s.opts.IsInstalled() {
		return nil
	}
	cmd := exec.Command(s.opts.RuncBinary, "delete", "--force", s.opts.ContainerID)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("runc delete: %w (%s)", err, stderr.String())
	}
	return nil
}
