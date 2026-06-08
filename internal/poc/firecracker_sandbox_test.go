package poc

import (
	"context"
	"testing"
)

func TestFirecrackerOptionsIsInstalled(t *testing.T) {
	o := DefaultFirecrackerOptions()
	_ = o.IsInstalled()
}

func TestFirecrackerAcquireNotInstalled(t *testing.T) {
	dir := t.TempDir()
	o := DefaultFirecrackerOptions()
	o.Binary = "/nonexistent/firecracker-binary-that-does-not-exist"
	o.SocketDir = dir
	o.BlockDir = dir
	fs := NewFirecrackerSandbox(o)
	if fs.Available() {
		t.Fatal("expected Available()=false when binary missing")
	}
	if _, err := fs.Acquire(context.Background()); err == nil {
		t.Fatal("expected Acquire() to error when firecracker missing")
	}
}

func TestFirecrackerSnapshotRestoreStubs(t *testing.T) {
	dir := t.TempDir()
	o := DefaultFirecrackerOptions()
	o.Binary = "/nonexistent/fc"
	o.SocketDir = dir
	o.BlockDir = dir
	fs := NewFirecrackerSandbox(o)
	if err := fs.Snapshot(context.Background(), &FCVM{ID: "x"}); err == nil {
		t.Fatal("expected Snapshot to be a no-op stub returning error")
	}
	if err := fs.Restore(context.Background(), &FCVM{ID: "x"}); err == nil {
		t.Fatal("expected Restore to be a no-op stub returning error")
	}
}

func TestFirecrackerMetricsInitialized(t *testing.T) {
	o := DefaultFirecrackerOptions()
	o.Binary = "/nonexistent/fc"
	fs := NewFirecrackerSandbox(o)
	m := fs.Metrics()
	if m.BootCount != 0 || m.ExecCount != 0 {
		t.Fatalf("expected zero counters, got %+v", m)
	}
}

func TestFirecrackerStopAll(t *testing.T) {
	o := DefaultFirecrackerOptions()
	o.Binary = "/nonexistent/fc"
	fs := NewFirecrackerSandbox(o)
	fs.StopAll()
	if len(fs.pool) != 0 || len(fs.inUse) != 0 {
		t.Fatal("expected empty pool after StopAll")
	}
}
