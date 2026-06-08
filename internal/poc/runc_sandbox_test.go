package poc

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuncOptionsIsInstalled(t *testing.T) {
	o := DefaultRuncOptions()
	if o.IsInstalled() {
		t.Log("runc is installed in this environment")
	} else {
		t.Log("runc not installed (typical for dev workstations)")
	}
}

func TestRuncGenerateBundle(t *testing.T) {
	dir := t.TempDir()
	o := DefaultRuncOptions()
	o.BundleDir = dir
	o.Cmd = []string{"/bin/sh", "/poc/poc.sh"}
	o.Env = []string{"PATH=/bin"}
	o.Workdir = "/"
	o.Timeout = 5_000_000_000

	rs := NewRuncSandbox(o)
	if err := rs.GenerateBundle(); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dir, "config.json")
	body, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	var spec runcSpec
	if err := json.Unmarshal(body, &spec); err != nil {
		t.Fatalf("config.json not valid runc spec: %v", err)
	}
	if spec.OCIVersion == "" {
		t.Fatal("expected ociVersion in spec")
	}
	if spec.Process == nil {
		t.Fatal("expected process section")
	}
	if !spec.Process.NoNewPrivileges {
		t.Fatal("expected noNewPrivileges=true")
	}
	if len(spec.Process.Capabilities.Bounding) != 0 {
		t.Fatal("expected empty bounding capabilities")
	}
	if spec.Linux == nil {
		t.Fatal("expected linux section")
	}
	if len(spec.Linux.Namespaces) == 0 {
		t.Fatal("expected at least one namespace")
	}
	hasPID, hasNet := false, false
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == "pid" {
			hasPID = true
		}
		if ns.Type == "network" {
			hasNet = true
		}
	}
	if !hasPID || !hasNet {
		t.Fatalf("expected pid and network namespaces, got pid=%v net=%v", hasPID, hasNet)
	}
	if !spec.Root.Readonly {
		t.Fatal("expected read-only root")
	}
	if spec.Linux.Resources == nil || spec.Linux.Resources.Pids == nil {
		t.Fatal("expected pids limit")
	}
	if spec.Linux.Resources.Pids.Limit != int64(o.PidsLimit) {
		t.Fatalf("expected pids limit %d, got %d", o.PidsLimit, spec.Linux.Resources.Pids.Limit)
	}
}

func TestRuncRunNotInstalled(t *testing.T) {
	dir := t.TempDir()
	o := DefaultRuncOptions()
	o.BundleDir = dir
	o.RuncBinary = "/nonexistent/runc-binary-that-does-not-exist"
	o.Cmd = []string{"/bin/sh"}
	rs := NewRuncSandbox(o)
	if _, err := rs.Run(context.Background()); err == nil {
		t.Fatal("expected error when runc binary is missing")
	}
}

func TestRuncNonLinuxOther(t *testing.T) {
	if !isLinux() {
		o := DefaultRuncOptions()
		if o.IsInstalled() {
			t.Skip("runc appears to be available")
		}
		rs := NewRuncSandbox(o)
		if err := rs.GenerateBundle(); err == nil {
			t.Fatal("expected error on non-Linux")
		}
	}
}

func isLinux() bool {
	return strings.Contains(strings.ToLower(os.Getenv("GOOS")), "linux") || os.Getenv("GOOS") == ""
}
