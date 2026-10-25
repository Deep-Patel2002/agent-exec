//go:build linux && integration

package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"agentexec/internal/model"
	"agentexec/internal/policy"
)

func integrationBackend(t *testing.T) *Linux {
	t.Helper()
	rootfs := os.Getenv("AGENTEXEC_ROOTFS")
	cg := os.Getenv("AGENTEXEC_CGROUP_ROOT")
	filter := os.Getenv("AGENTEXEC_SECCOMP")
	state := os.Getenv("AGENTEXEC_TEST_STATE")
	if rootfs == "" || cg == "" || filter == "" || state == "" {
		t.Fatal("integration configuration missing; use tools/run-integration.sh inside a delegated cgroup")
	}
	b, err := NewLinux(Options{RootFS: rootfs, CgroupRoot: cg, WorkspaceRoot: filepath.Join(state, "workspaces"), BwrapPath: "/usr/bin/bwrap", SeccompPath: filter, Policy: policy.Default()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Error(err)
		}
	})
	return b
}
func runPython(t *testing.T, b *Linux, source string, timeout time.Duration) model.Result {
	t.Helper()
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	r, err := b.Run(ctx, model.Task{ID: hex.EncodeToString(id), Request: model.Request{Argv: []string{"/usr/bin/python3", "-I", "/input/main.py"}, Files: map[string]string{"main.py": source}}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestRealSandboxBoundaries(t *testing.T) {
	b := integrationBackend(t)
	tests := []struct{ name, source, output string }{
		{"legitimate_workload", "import json,os\nprint(json.dumps({'sum':sum(range(100)), 'cwd':os.getcwd()},sort_keys=True))", `{"cwd": "/work", "sum": 4950}`},
		{"host_files_absent", "import os\nassert not os.path.exists('/etc/shadow')\nassert not os.path.exists('/home/agentexec')\nprint('isolated')", "isolated"},
		{"no_inherited_secret", "import os\nassert os.getenv('AGENTEXEC_TEST_CANARY') is None\nprint('clean')", "clean"},
		{"rootfs_readonly", "import errno\ntry:\n open('/etc/passwd','w')\n raise AssertionError('rootfs writable')\nexcept OSError as e:\n assert e.errno in (errno.EROFS,errno.EACCES,errno.EPERM)\nprint('readonly')", "readonly"},
		{"inputs_readonly", "import errno\ntry:\n open('/input/main.py','w')\n raise AssertionError('input writable')\nexcept OSError as e:\n assert e.errno in (errno.EROFS,errno.EACCES,errno.EPERM)\nprint('readonly')", "readonly"},
		{"network_denied", "import socket,errno\ntry:\n socket.socket()\n raise AssertionError('network syscall allowed')\nexcept OSError as e:\n assert e.errno == errno.EPERM\nprint('network denied')", "network denied"},
		{"namespace_creation_denied", "import ctypes,errno\nlibc=ctypes.CDLL(None,use_errno=True)\nassert libc.unshare(0x10000000)==-1\nassert ctypes.get_errno()==errno.EPERM\nprint('unshare denied')", "unshare denied"},
		{"seccomp_and_nnp", "s=open('/proc/self/status').read()\nassert 'Seccomp:\t2' in s\nassert 'NoNewPrivs:\t1' in s\nprint('hardened')", "hardened"},
		{"writable_ephemeral_workspace", "open('/work/result','w').write('ok')\nopen('/tmp/scratch','w').write('ok')\nprint('writable')", "writable"},
	}
	t.Setenv("AGENTEXEC_TEST_CANARY", "host-secret-must-not-leak")
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := runPython(t, b, tc.source, 3*time.Second)
			if r.State != model.Succeeded || strings.TrimSpace(r.Stdout) != tc.output {
				t.Fatalf("state=%s output=%q stderr=%q", r.State, r.Stdout, r.Stderr)
			}
		})
	}
}
func TestRealResourceLimitsAndCleanup(t *testing.T) {
	b := integrationBackend(t)
	t.Run("output_limit", func(t *testing.T) {
		r := runPython(t, b, "import os\nos.write(1,b'x'*200000)", 3*time.Second)
		if r.State != model.OutputLimit || len(r.Stdout)+len(r.Stderr) != 65536 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("deadline_and_descendants", func(t *testing.T) {
		r := runPython(t, b, "import os,time\nif os.fork()==0:\n os.setsid()\n while True: time.sleep(1)\nwhile True: time.sleep(1)", 250*time.Millisecond)
		if r.State != model.TimedOut {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("memory_limit", func(t *testing.T) {
		r := runPython(t, b, "a=bytearray(512*1024*1024)\nprint(len(a))", 5*time.Second)
		if r.State != model.ResourceExhausted || r.Usage.OOMKills < 1 {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("process_limit", func(t *testing.T) {
		r := runPython(t, b, "import os,time\nchildren=[]\ntry:\n for i in range(200):\n  pid=os.fork()\n  if pid==0:\n   time.sleep(5);os._exit(0)\n  children.append(pid)\nexcept OSError:\n print('limited',flush=True)\nfinally:\n for pid in children:\n  os.kill(pid,9)\n for pid in children:\n  os.waitpid(pid,0)", 4*time.Second)
		if r.Usage.PidsLimitHits < 1 || !strings.Contains(r.Stdout, "limited") {
			t.Fatalf("%+v", r)
		}
	})
	t.Run("cpu_bandwidth_limit", func(t *testing.T) {
		b.options.Policy.CPUMillis = 100
		r := runPython(t, b, "while True: pass", 1200*time.Millisecond)
		b.options.Policy.CPUMillis = 1000
		if r.State != model.TimedOut || r.Usage.CPUUsec < 50000 || r.Usage.CPUUsec > 350000 {
			t.Fatalf("CPU bandwidth not bounded: %+v", r)
		}
	})
	entries, err := os.ReadDir(b.options.CgroupRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "job-") {
			t.Fatal("job cgroup leaked: " + e.Name())
		}
	}
	entries, err = os.ReadDir(b.options.WorkspaceRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != ".lock" {
			t.Fatal("workspace leaked")
		}
	}
}
