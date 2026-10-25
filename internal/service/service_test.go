package service

import (
	"agentexec/internal/audit"
	"agentexec/internal/model"
	"agentexec/internal/policy"
	"agentexec/internal/store"
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type fakeBackend struct {
	block   bool
	calls   atomic.Int32
	failure bool
}

func (f *fakeBackend) Run(ctx context.Context, _ model.Task) (model.Result, error) {
	f.calls.Add(1)
	if f.failure {
		return model.Result{}, errors.New("backend unavailable")
	}
	if f.block {
		<-ctx.Done()
		return model.Result{State: model.Cancelled, ExitCode: -1}, nil
	}
	return model.Result{State: model.Succeeded, Stdout: "ok", ExitCode: 0}, nil
}
func (*fakeBackend) Close() error { return nil }
func newTestManager(t *testing.T, f *fakeBackend, o Options) *Manager {
	t.Helper()
	dir := t.TempDir()
	s, err := store.New(filepath.Join(dir, "records"), o.RetainedJobs)
	if err != nil {
		t.Fatal(err)
	}
	a, err := audit.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	m, err := New(policy.Default(), f, s, a, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := m.Close(ctx); err != nil {
			t.Error(err)
		}
		a.Close()
	})
	return m
}
func waitState(t *testing.T, m *Manager, id string, terminal bool) model.Job {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		j, err := m.Get("alice", id)
		if err != nil {
			t.Fatal(err)
		}
		if (terminal && j.State.Terminal()) || (!terminal && j.State == model.Running) {
			return j
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("state transition timeout")
	return model.Job{}
}
func TestLifecycleOwnershipAndRetention(t *testing.T) {
	f := &fakeBackend{}
	m := newTestManager(t, f, Options{1, 2, 2})
	for i := 0; i < 4; i++ {
		j, err := m.Submit("alice", model.Request{Argv: []string{"/bin/sh"}})
		if err != nil {
			t.Fatal(err)
		}
		j = waitState(t, m, j.ID, true)
		if j.State != model.Succeeded || j.Result.Stdout != "ok" {
			t.Fatal(j)
		}
		if _, err := m.Get("bob", j.ID); !errors.Is(err, ErrNotFound) {
			t.Fatal("cross-principal access")
		}
	}
	if len(m.List("alice")) != 2 || len(m.List("bob")) != 0 {
		t.Fatal("retention or ownership failed")
	}
}
func TestCapacityAndQueuedCancellation(t *testing.T) {
	f := &fakeBackend{block: true}
	m := newTestManager(t, f, Options{1, 2, 8})
	a, _ := m.Submit("alice", model.Request{Argv: []string{"/bin/sh"}})
	waitState(t, m, a.ID, false)
	b, _ := m.Submit("alice", model.Request{Argv: []string{"/bin/sh"}})
	if _, err := m.Submit("alice", model.Request{Argv: []string{"/bin/sh"}}); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if err := m.Cancel("bob", a.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("cross-principal cancel")
	}
	m.Cancel("alice", b.ID)
	m.Cancel("alice", a.ID)
	if waitState(t, m, b.ID, true).State != model.Cancelled {
		t.Fatal("queued work not cancelled")
	}
	if f.calls.Load() != 1 {
		t.Fatal("cancelled queued job executed")
	}
}
func TestDeadline(t *testing.T) {
	m := newTestManager(t, &fakeBackend{block: true}, Options{1, 1, 8})
	j, _ := m.Submit("alice", model.Request{Argv: []string{"/bin/sh"}, TimeoutMS: 100})
	if waitState(t, m, j.ID, true).State != model.TimedOut {
		t.Fatal("deadline not enforced")
	}
}
func TestBackendFailureQuarantinesService(t *testing.T) {
	m := newTestManager(t, &fakeBackend{failure: true}, Options{1, 1, 8})
	j, _ := m.Submit("alice", model.Request{Argv: []string{"/bin/sh"}})
	if waitState(t, m, j.ID, true).State != model.Failed {
		t.Fatal("infrastructure failure misclassified as cancellation")
	}
	if m.Stats().Ready {
		t.Fatal("service stayed ready")
	}
	if _, err := m.Submit("alice", model.Request{Argv: []string{"/bin/sh"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
}

type brokenStore struct{}

func (brokenStore) Load() ([]model.Job, error) { return nil, nil }
func (brokenStore) Save(model.Job) error       { return errors.New("storage unavailable") }
func (brokenStore) Delete(string) error        { return nil }
func TestStorageFailurePreventsExecution(t *testing.T) {
	a, err := audit.Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	f := &fakeBackend{}
	m, err := New(policy.Default(), f, brokenStore{}, a, Options{1, 1, 8})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	if _, err := m.Submit("alice", model.Request{Argv: []string{"/bin/sh"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if f.calls.Load() != 0 || m.Stats().Ready {
		t.Fatal("executed without durable storage")
	}
}
func TestRestartDoesNotReplay(t *testing.T) {
	dir := t.TempDir()
	s, _ := store.New(filepath.Join(dir, "records"), 8)
	id := "12345678901234567890123456789012"
	s.Save(model.Job{ID: id, Principal: "alice", State: model.Running, CreatedAt: time.Now()})
	a, _ := audit.Open(filepath.Join(dir, "audit.jsonl"))
	defer a.Close()
	f := &fakeBackend{}
	m, err := New(policy.Default(), f, s, a, Options{1, 1, 8})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	j, _ := m.Get("alice", id)
	if j.State != model.Interrupted || f.calls.Load() != 0 {
		t.Fatal("restart replayed work")
	}
}

type brokenAudit struct{}

func (brokenAudit) Append(string, string, string, string) error { return errors.New("disk full") }
func TestAuditFailurePreventsExecution(t *testing.T) {
	s, _ := store.New(t.TempDir(), 8)
	f := &fakeBackend{}
	m, err := New(policy.Default(), f, s, brokenAudit{}, Options{1, 1, 8})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close(context.Background())
	if _, err := m.Submit("alice", model.Request{Argv: []string{"/bin/sh"}}); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if f.calls.Load() != 0 || m.Stats().Ready {
		t.Fatal("executed without durable audit")
	}
}
