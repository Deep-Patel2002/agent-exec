package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"agentexec/internal/api"
	"agentexec/internal/audit"
	"agentexec/internal/config"
	"agentexec/internal/model"
	"agentexec/internal/sandbox"
	"agentexec/internal/service"
	"agentexec/internal/store"
)

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if err := run(); err != nil {
		slog.Error("server stopped", "error", err)
		os.Exit(1)
	}
}
func run() error {
	path := flag.String("config", "/etc/agent-exec/config.json", "operator configuration")
	check := flag.Bool("check", false, "validate configuration and execute sandbox readiness probe, then exit")
	flag.Parse()
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	auth, err := api.LoadAuth(c.TokensFile)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(c.StateDir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("state directory must be private and not a symlink")
	}
	backend, err := sandbox.NewLinux(sandbox.Options{RootFS: c.RootFS, CgroupRoot: c.CgroupRoot, WorkspaceRoot: filepath.Join(c.StateDir, "workspaces"), BwrapPath: c.BwrapPath, SeccompPath: c.SeccompPath, Policy: c.Policy})
	if err != nil {
		return err
	}
	defer backend.Close()
	// Readiness tests the real atomic spawn, mount policy, and seccomp filter.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	probeSource := "import os,socket,errno\ns=open('/proc/self/status').read()\nassert 'Seccomp:\\t2' in s and 'NoNewPrivs:\\t1' in s\nassert not os.path.exists('/etc/shadow')\ntry:\n socket.socket()\n raise AssertionError('network policy not enforced')\nexcept OSError as e:\n assert e.errno==errno.EPERM\nprint('agentexec-ready')"
	probe, err := backend.Run(ctx, model.Task{ID: "00000000000000000000000000000000", Request: model.Request{Argv: []string{"/usr/bin/python3", "-I", "-c", probeSource}}})
	cancel()
	if err != nil {
		return fmt.Errorf("sandbox readiness probe: %w", err)
	}
	if probe.State != model.Succeeded || probe.Stdout != "agentexec-ready\n" {
		return fmt.Errorf("sandbox readiness probe failed: %s: %s", probe.State, probe.Stderr)
	}
	if *check {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"ready": true, "backend": "bubblewrap+cgroup-v2+seccomp", "probe": probe.Usage})
	}
	log, err := audit.Open(filepath.Join(c.StateDir, "audit.jsonl"))
	if err != nil {
		return err
	}
	defer log.Close()
	if err := log.Append("service_started", "", "", ""); err != nil {
		return err
	}
	persistence, err := store.New(filepath.Join(c.StateDir, "records"), c.RetainedJobs)
	if err != nil {
		return err
	}
	m, err := service.New(c.Policy, backend, persistence, log, service.Options{Workers: c.Workers, MaxInFlight: c.MaxInFlight, RetainedJobs: c.RetainedJobs})
	if err != nil {
		return err
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			slog.Error("shutdown cleanup failed", "error", err)
		}
	}()
	listener, err := net.Listen("tcp", c.Listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: api.New(m, auth), ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	errorsCh := make(chan error, 1)
	go func() { errorsCh <- srv.Serve(listener) }()
	slog.Info("service ready", "listen", listener.Addr().String(), "workers", c.Workers)
	sig, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errorsCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-sig.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}
