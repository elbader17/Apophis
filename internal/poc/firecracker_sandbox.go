package poc

import (
	"context"
	"fmt"
	"os/exec"
	"sync"
	"sync/atomic"
	"time"
)

type FCState string

const (
	FCStateIdle   FCState = "idle"
	FCStateBooted FCState = "booted"
	FCStateBusy   FCState = "busy"
	FCStateStopped FCState = "stopped"
)

type FCMetrics struct {
	BootMs    int64 `json:"boot_ms"`
	ExecMs    int64 `json:"exec_ms"`
	SnapshotMs int64 `json:"snapshot_ms"`
	RestoreMs int64 `json:"restore_ms"`
	BootCount int64 `json:"boot_count"`
	ExecCount int64 `json:"exec_count"`
	TotalVMPaused int64 `json:"total_vm_paused"`
}

type FCVM struct {
	ID         string
	State      FCState
	APISocket  string
	BlockDev   string
	KernelImg  string
	Rootfs     string
	VCPUCount  int
	MemSizeMiB int
	bootedAt   time.Time
	lastUsed   time.Time
}

type FirecrackerOptions struct {
	Binary       string
	KernelImage  string
	Rootfs       string
	VCPUCount    int
	MemSizeMiB   int
	PoolSize     int
	SocketDir    string
	BlockDir     string
}

func DefaultFirecrackerOptions() FirecrackerOptions {
	return FirecrackerOptions{
		Binary:     "firecracker",
		VCPUCount:  1,
		MemSizeMiB: 256,
		PoolSize:   2,
		SocketDir:  "/tmp/apophis-fc-sockets",
		BlockDir:   "/tmp/apophis-fc-blocks",
	}
}

func (o FirecrackerOptions) IsInstalled() bool {
	bin := o.Binary
	if bin == "" {
		bin = "firecracker"
	}
	_, err := exec.LookPath(bin)
	return err == nil
}

type FirecrackerSandbox struct {
	opts    FirecrackerOptions
	mu      sync.Mutex
	pool    []*FCVM
	inUse   map[string]*FCVM
	metrics FCMetrics
	enabled bool
	counter uint64
}

func NewFirecrackerSandbox(opts FirecrackerOptions) *FirecrackerSandbox {
	if opts.Binary == "" {
		opts.Binary = "firecracker"
	}
	if opts.VCPUCount == 0 {
		opts.VCPUCount = 1
	}
	if opts.MemSizeMiB == 0 {
		opts.MemSizeMiB = 256
	}
	if opts.PoolSize == 0 {
		opts.PoolSize = 2
	}
	return &FirecrackerSandbox{
		opts:  opts,
		pool:  make([]*FCVM, 0, opts.PoolSize),
		inUse: make(map[string]*FCVM),
	}
}

func (s *FirecrackerSandbox) Available() bool {
	if !s.opts.IsInstalled() {
		return false
	}
	// Real implementation would also check KVM is available (/dev/kvm exists and is r/w).
	// TODO(phase-5): check /dev/kvm accessibility for the configured user.
	return s.opts.IsInstalled()
}

func (s *FirecrackerSandbox) Metrics() FCMetrics {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.metrics
}

func (s *FirecrackerSandbox) Acquire(ctx context.Context) (*FCVM, error) {
	if !s.Available() {
		return nil, fmt.Errorf("firecracker not available: binary %q not found or KVM not accessible", s.opts.Binary)
	}

	s.mu.Lock()
	if len(s.pool) > 0 {
		vm := s.pool[len(s.pool)-1]
		s.pool = s.pool[:len(s.pool)-1]
		s.inUse[vm.ID] = vm
		vm.State = FCStateBusy
		vm.lastUsed = time.Now()
		s.mu.Unlock()
		return vm, nil
	}
	s.mu.Unlock()

	atomic.AddUint64(&s.counter, 1)
	vmID := fmt.Sprintf("fc-%d-%d", time.Now().UnixNano(), atomic.LoadUint64(&s.counter))
	vm := &FCVM{
		ID:         vmID,
		State:      FCStateIdle,
		APISocket:  fmt.Sprintf("%s/%s.sock", s.opts.SocketDir, vmID),
		BlockDev:   fmt.Sprintf("%s/%s.ext4", s.opts.BlockDir, vmID),
		KernelImg:  s.opts.KernelImage,
		Rootfs:     s.opts.Rootfs,
		VCPUCount:  s.opts.VCPUCount,
		MemSizeMiB: s.opts.MemSizeMiB,
	}

	t0 := time.Now()
	if err := s.bootVM(ctx, vm); err != nil {
		return nil, fmt.Errorf("boot vm: %w", err)
	}
	bootMs := time.Since(t0).Milliseconds()

	s.mu.Lock()
	s.metrics.BootMs = (s.metrics.BootMs*s.metrics.BootCount + bootMs) / (s.metrics.BootCount + 1)
	s.metrics.BootCount++
	s.inUse[vm.ID] = vm
	vm.State = FCStateBusy
	vm.lastUsed = time.Now()
	s.mu.Unlock()
	return vm, nil
}

func (s *FirecrackerSandbox) Release(ctx context.Context, vm *FCVM) error {
	if vm == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inUse, vm.ID)
	if vm.State == FCStateBusy {
		// Return to pool: snapshot+restore happens on next acquire.
		// TODO(phase-5): implement actual snapshot of vm into pool.
		vm.State = FCStateIdle
		s.pool = append(s.pool, vm)
	}
	return nil
}

func (s *FirecrackerSandbox) Snapshot(ctx context.Context, vm *FCVM) error {
	if vm == nil {
		return fmt.Errorf("vm is nil")
	}
	t0 := time.Now()
	// TODO(phase-5): send PauseInstance PUT /snapshot/create over API socket.
	defer func() {
		s.mu.Lock()
		s.metrics.SnapshotMs = time.Since(t0).Milliseconds()
		s.mu.Unlock()
	}()
	return fmt.Errorf("snapshot: not yet implemented (firecracker stub — see docs/POC_EXECUTOR.md §5)")
}

func (s *FirecrackerSandbox) Restore(ctx context.Context, vm *FCVM) error {
	if vm == nil {
		return fmt.Errorf("vm is nil")
	}
	t0 := time.Now()
	// TODO(phase-5): send LoadSnapshot PUT /snapshot/load over API socket.
	defer func() {
		s.mu.Lock()
		s.metrics.RestoreMs = time.Since(t0).Milliseconds()
		s.mu.Unlock()
	}()
	return fmt.Errorf("restore: not yet implemented (firecracker stub — see docs/POC_EXECUTOR.md §5)")
}

func (s *FirecrackerSandbox) Exec(ctx context.Context, vm *FCVM, cmd []string, env []string) (*RunResult, error) {
	if !s.Available() {
		return nil, fmt.Errorf("firecracker not available")
	}
	if vm == nil {
		return nil, fmt.Errorf("vm is nil")
	}
	t0 := time.Now()
	// TODO(phase-5): communicate with guest over vsock to run cmd, stream stdout.
	defer func() {
		s.mu.Lock()
		s.metrics.ExecMs = time.Since(t0).Milliseconds()
		s.metrics.ExecCount++
		s.mu.Unlock()
	}()
	return nil, fmt.Errorf("exec: not yet implemented (firecracker stub — see docs/POC_EXECUTOR.md §5; requires vsock agent in guest)")
}

func (s *FirecrackerSandbox) bootVM(ctx context.Context, vm *FCVM) error {
	// TODO(phase-5): start firecracker process with --api-sock, PUT /machine-config,
	// PUT /boot-source, PUT /drives/rootfs, PUT /actions (InstanceStart).
	// For now, return an error so callers know this is a stub.
	return fmt.Errorf("bootVM: not yet implemented (firecracker stub — see docs/POC_EXECUTOR.md §5)")
}

func (s *FirecrackerSandbox) StopAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, vm := range s.pool {
		if vm.State == FCStateBooted || vm.State == FCStateBusy {
			// TODO(phase-5): send ShutdownInstance / KillInstance via API socket
			vm.State = FCStateStopped
		}
	}
	for _, vm := range s.inUse {
		vm.State = FCStateStopped
	}
	s.pool = nil
	s.inUse = map[string]*FCVM{}
	s.metrics.TotalVMPaused = int64(len(s.inUse))
}
