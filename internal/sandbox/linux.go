//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"agentexec/internal/model"
	"agentexec/internal/policy"
	"agentexec/internal/store"
)

type Options struct {
	RootFS        string
	CgroupRoot    string
	WorkspaceRoot string
	BwrapPath     string
	SeccompPath   string
	Policy        policy.Policy
}
type Linux struct {
	options Options
	lock    *os.File
	mu      sync.Mutex
	closed  bool
}

func NewLinux(o Options) (*Linux, error) {
	if os.Geteuid() == 0 {
		return nil, errors.New("refusing to run execution service as root; use a dedicated unprivileged account")
	}
	if err := o.Policy.Validate(); err != nil {
		return nil, err
	}
	for _, p := range []string{o.RootFS, o.WorkspaceRoot, o.BwrapPath, o.SeccompPath} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return nil, errors.New("backend paths must be clean absolute paths")
		}
	}
	if within(o.RootFS, o.WorkspaceRoot) || within(o.WorkspaceRoot, o.RootFS) {
		return nil, errors.New("rootfs and workspaces must not overlap")
	}
	if o.RootFS == "/" {
		return nil, errors.New("host root cannot be used as a sandbox image")
	}
	if err := trusted(o.RootFS, true); err != nil {
		return nil, fmt.Errorf("rootfs: %w", err)
	}
	if err := trusted(filepath.Join(o.RootFS, ".sha256-manifest"), false); err != nil {
		return nil, fmt.Errorf("rootfs requires an operator-built image manifest: %w", err)
	}
	if err := trusted(o.BwrapPath, false); err != nil {
		return nil, fmt.Errorf("bubblewrap: %w", err)
	}
	if err := trusted(o.SeccompPath, false); err != nil {
		return nil, fmt.Errorf("seccomp: %w", err)
	}
	info, err := os.Stat(o.SeccompPath)
	if err != nil || info.Size() < 32 || info.Size()%8 != 0 {
		return nil, errors.New("invalid seccomp BPF program")
	}
	for _, p := range o.Policy.AllowedExecutables {
		target, err := filepath.EvalSymlinks(filepath.Join(o.RootFS, p))
		if err != nil || !within(o.RootFS, target) {
			return nil, errors.New("allowed executable missing or resolves outside rootfs")
		}
		info, err := os.Stat(target)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return nil, errors.New("allowed executable is not executable")
		}
	}
	if err := os.MkdirAll(o.WorkspaceRoot, 0700); err != nil {
		return nil, err
	}
	info, err = os.Lstat(o.WorkspaceRoot)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("workspace root must be a private directory")
	}
	lock, err := os.OpenFile(filepath.Join(o.WorkspaceRoot, ".lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, errors.New("workspace root is already in use")
	}
	cleanup := func(err error) (*Linux, error) { lock.Close(); return nil, err }
	if o.CgroupRoot == "auto" {
		data, err := os.ReadFile("/proc/self/cgroup")
		if err != nil {
			return cleanup(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "0::") {
				o.CgroupRoot = filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(line, "0::"))
			}
		}
		if o.CgroupRoot == "auto" || o.CgroupRoot == "/sys/fs/cgroup" {
			return cleanup(errors.New("auto cgroup delegation requires a systemd service with Delegate=yes"))
		}
	}
	if !filepath.IsAbs(o.CgroupRoot) || filepath.Clean(o.CgroupRoot) != o.CgroupRoot {
		return cleanup(errors.New("invalid cgroup root"))
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(o.CgroupRoot, &st); err != nil || uint64(st.Type) != 0x63677270 {
		return cleanup(errors.New("a delegated cgroup v2 hierarchy is required"))
	}
	// Move only this trusted supervisor to its own leaf before enabling controllers.
	if err := os.Mkdir(filepath.Join(o.CgroupRoot, "supervisor"), 0750); err != nil && !os.IsExist(err) {
		return cleanup(err)
	}
	if err := os.WriteFile(filepath.Join(o.CgroupRoot, "supervisor", "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
		return cleanup(fmt.Errorf("move supervisor: %w", err))
	}
	if err := os.WriteFile(filepath.Join(o.CgroupRoot, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0600); err != nil {
		return cleanup(fmt.Errorf("enable delegated controllers: %w", err))
	}
	b := &Linux{options: o, lock: lock}
	entries, err := os.ReadDir(o.CgroupRoot)
	if err != nil {
		return cleanup(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "job-") {
			if !store.ValidID(strings.TrimPrefix(e.Name(), "job-")) {
				return cleanup(errors.New("unknown job cgroup; operator inspection required"))
			}
			if err := killRemove(filepath.Join(o.CgroupRoot, e.Name())); err != nil {
				return cleanup(fmt.Errorf("recover cgroup: %w", err))
			}
		}
	}
	entries, err = os.ReadDir(o.WorkspaceRoot)
	if err != nil {
		return cleanup(err)
	}
	for _, e := range entries {
		if e.Name() == ".lock" {
			continue
		}
		if !store.ValidID(e.Name()) {
			return cleanup(errors.New("unknown workspace entry"))
		}
		if err := os.RemoveAll(filepath.Join(o.WorkspaceRoot, e.Name())); err != nil {
			return cleanup(err)
		}
	}
	return b, nil
}

func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
func trusted(path string, dir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || info.Mode().Perm()&0022 != 0 || info.Mode()&(os.ModeSymlink|os.ModeSetuid|os.ModeSetgid) != 0 {
		return errors.New("path must be root-owned, not group/world writable, and not a symlink or setuid binary")
	}
	if info.IsDir() != dir || (!dir && !info.Mode().IsRegular()) {
		return errors.New("unexpected path type")
	}
	return nil
}

func (b *Linux) Run(parent context.Context, task model.Task) (result model.Result, err error) {
	if !store.ValidID(task.ID) {
		return result, errors.New("invalid task identity")
	}
	b.mu.Lock()
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return result, errors.New("backend closed")
	}
	r, err := b.options.Policy.Normalize(task.Request)
	if err != nil {
		return result, err
	}
	workspace := filepath.Join(b.options.WorkspaceRoot, task.ID)
	if err := os.Mkdir(workspace, 0700); err != nil {
		return result, err
	}
	defer func() {
		if e := os.RemoveAll(workspace); e != nil {
			err = errors.Join(err, fmt.Errorf("workspace cleanup: %w", e))
		}
	}()
	input := filepath.Join(workspace, "input")
	if err := os.Mkdir(input, 0700); err != nil {
		return result, err
	}
	for name, content := range r.Files {
		target := filepath.Join(input, filepath.FromSlash(name))
		if !within(input, target) {
			return result, errors.New("input path escapes workspace")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return result, err
		}
		if err := os.WriteFile(target, []byte(content), 0400); err != nil {
			return result, err
		}
	}
	cgroup := filepath.Join(b.options.CgroupRoot, "job-"+task.ID)
	if err := os.Mkdir(cgroup, 0750); err != nil {
		return result, err
	}
	defer func() {
		if e := killRemove(cgroup); e != nil {
			err = errors.Join(err, fmt.Errorf("cgroup cleanup: %w", e))
		}
	}()
	settings := map[string]string{"memory.max": strconv.FormatInt(b.options.Policy.MemoryBytes, 10), "memory.swap.max": "0", "memory.oom.group": "1", "pids.max": strconv.Itoa(b.options.Policy.PidsMax), "cpu.max": fmt.Sprintf("%d 100000", b.options.Policy.CPUMillis*100)}
	for name, value := range settings {
		if err := os.WriteFile(filepath.Join(cgroup, name), []byte(value), 0600); err != nil {
			return result, fmt.Errorf("cgroup %s: %w", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(cgroup, "cgroup.kill")); err != nil {
		return result, errors.New("kernel cgroup.kill support is mandatory")
	}
	cg, err := os.Open(cgroup)
	if err != nil {
		return result, err
	}
	defer cg.Close()
	filter, err := os.Open(b.options.SeccompPath)
	if err != nil {
		return result, err
	}
	defer filter.Close()
	args := []string{"--unshare-all", "--unshare-user", "--unshare-cgroup", "--die-with-parent", "--new-session", "--disable-userns", "--cap-drop", "ALL", "--clearenv", "--ro-bind", b.options.RootFS, "/", "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/work", "--ro-bind", input, "/input", "--chdir", "/work", "--setenv", "PATH", "/usr/bin:/bin", "--setenv", "HOME", "/work", "--setenv", "LANG", "C.UTF-8", "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--seccomp", "3", "--"}
	args = append(args, r.Argv...)
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	capture := NewCapture(b.options.Policy.OutputBytes, cancel)
	cmd := exec.Command(b.options.BwrapPath, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.Stdin = strings.NewReader("")
	cmd.Stdout = capture.Stdout()
	cmd.Stderr = capture.Stderr()
	cmd.ExtraFiles = []*os.File{filter}
	// CLONE_INTO_CGROUP places the launcher before any untrusted instruction runs.
	// There is deliberately no post-spawn migration fallback.
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd()), Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = 2 * time.Second
	start := time.Now()
	// Linux ties PDEATHSIG to the creating OS thread, not merely its process.
	// Keep that thread alive for the complete workload lifetime.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := cmd.Start(); err != nil {
		return result, fmt.Errorf("atomic cgroup spawn failed: %w", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var waitErr error
	select {
	case waitErr = <-done:
	case <-ctx.Done():
		if e := os.WriteFile(filepath.Join(cgroup, "cgroup.kill"), []byte("1"), 0600); e != nil {
			_ = cmd.Process.Kill()
			return result, fmt.Errorf("kill workload: %w", e)
		}
		select {
		case waitErr = <-done:
		case <-time.After(3 * time.Second):
			return result, errors.New("workload did not exit after cgroup kill")
		}
	}
	// Kill any detached descendants before recording completion or removing mounts.
	if e := os.WriteFile(filepath.Join(cgroup, "cgroup.kill"), []byte("1"), 0600); e != nil {
		return result, e
	}
	result.Stdout, result.Stderr, result.OutputTruncated = capture.Snapshot()
	result.ExitCode = cmd.ProcessState.ExitCode()
	result.State = model.Succeeded
	result.Usage.WallMS = time.Since(start).Milliseconds()
	if result.Usage.CPUUsec, err = counter(filepath.Join(cgroup, "cpu.stat"), "usage_usec"); err != nil {
		return result, err
	}
	if result.Usage.OOMKills, err = counter(filepath.Join(cgroup, "memory.events"), "oom_kill"); err != nil {
		return result, err
	}
	if result.Usage.PidsLimitHits, err = counter(filepath.Join(cgroup, "pids.events"), "max"); err != nil {
		return result, err
	}
	if data, e := os.ReadFile(filepath.Join(cgroup, "memory.peak")); e == nil {
		if n, e := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64); e == nil {
			result.Usage.MemoryPeakBytes = &n
		}
	}
	switch {
	case result.OutputTruncated:
		result.State = model.OutputLimit
	case parent.Err() == context.DeadlineExceeded:
		result.State = model.TimedOut
	case parent.Err() != nil:
		result.State = model.Cancelled
	case result.Usage.OOMKills > 0:
		result.State = model.ResourceExhausted
	case waitErr != nil:
		var exit *exec.ExitError
		if !errors.As(waitErr, &exit) {
			return result, waitErr
		}
		result.State = model.Failed
	}
	return result, nil
}
func counter(path, key string) (uint64, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == key {
			return strconv.ParseUint(fields[1], 10, 64)
		}
	}
	return 0, fmt.Errorf("mandatory cgroup counter %s is missing", key)
}
func killRemove(path string) error {
	if err := os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0600); err != nil {
		return err
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		err := os.Remove(path)
		if err == nil || os.IsNotExist(err) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("cgroup remains populated: %w", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
func (b *Linux) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	return b.lock.Close()
}
