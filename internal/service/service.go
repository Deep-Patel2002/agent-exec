// Package service owns admission, durable job transitions, and worker lifecycle.
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"agentexec/internal/model"
	"agentexec/internal/policy"
	"agentexec/internal/sandbox"
)

var (
	ErrBusy        = errors.New("execution capacity exhausted")
	ErrUnavailable = errors.New("service is not accepting work")
	ErrNotFound    = errors.New("job not found")
)

type Persistence interface {
	Save(model.Job) error
	Delete(string) error
	Load() ([]model.Job, error)
}
type Auditor interface {
	Append(string, string, string, string) error
}
type Options struct {
	Workers      int
	MaxInFlight  int
	RetainedJobs int
}
type entry struct {
	job     model.Job
	request model.Request
	ctx     context.Context
	cancel  context.CancelFunc
}
type Stats struct {
	Ready     bool   `json:"ready"`
	InFlight  int    `json:"in_flight"`
	Retained  int    `json:"retained"`
	Submitted uint64 `json:"submitted_since_start"`
	Completed uint64 `json:"completed_since_start"`
}
type Manager struct {
	mu        sync.Mutex
	policy    policy.Policy
	backend   sandbox.Backend
	store     Persistence
	audit     Auditor
	options   Options
	jobs      map[string]*entry
	queue     chan *entry
	wg        sync.WaitGroup
	closed    bool
	unhealthy bool
	inFlight  int
	submitted uint64
	completed uint64
}

func New(p policy.Policy, backend sandbox.Backend, store Persistence, audit Auditor, o Options) (*Manager, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	if o.Workers < 1 || o.Workers > 32 || o.MaxInFlight < o.Workers || o.MaxInFlight > 256 || o.RetainedJobs < o.MaxInFlight || o.RetainedJobs > 10000 {
		return nil, errors.New("invalid worker, admission, or retention bounds")
	}
	if int64(o.RetainedJobs)*int64(p.OutputBytes) > 256<<20 {
		return nil, errors.New("retained output budget must not exceed 256 MiB")
	}
	jobs, err := store.Load()
	if err != nil {
		return nil, err
	}
	if len(jobs) > o.RetainedJobs {
		return nil, errors.New("stored records exceed retention bound")
	}
	m := &Manager{policy: p, backend: backend, store: store, audit: audit, options: o, jobs: map[string]*entry{}, queue: make(chan *entry, o.MaxInFlight)}
	for _, j := range jobs {
		switch j.State {
		case model.Queued, model.Running, model.Succeeded, model.Failed, model.TimedOut, model.Cancelled, model.OutputLimit, model.ResourceExhausted, model.Interrupted:
		default:
			return nil, errors.New("invalid persisted state")
		}
		if !j.State.Terminal() {
			now := time.Now().UTC()
			j.State = model.Interrupted
			j.FinishedAt = &now
			j.Result = &model.Result{State: model.Interrupted, ExitCode: -1, Error: "service restarted; job was not replayed"}
			if err := audit.Append("job_recovered", j.ID, j.Principal, string(j.State)); err != nil {
				return nil, err
			}
			if err := store.Save(j); err != nil {
				return nil, err
			}
		}
		m.jobs[j.ID] = &entry{job: j}
	}
	for i := 0; i < o.Workers; i++ {
		m.wg.Add(1)
		go m.worker()
	}
	return m, nil
}

func (m *Manager) Submit(principal string, r model.Request) (model.Job, error) {
	r, err := m.policy.Normalize(r)
	if err != nil {
		return model.Job{}, err
	}
	if principal == "" || len(principal) > 80 {
		return model.Job{}, errors.New("invalid principal")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.unhealthy {
		return model.Job{}, ErrUnavailable
	}
	if m.inFlight >= m.options.MaxInFlight {
		return model.Job{}, ErrBusy
	}
	if len(m.jobs) >= m.options.RetainedJobs {
		var oldest *entry
		for _, e := range m.jobs {
			if e.job.State.Terminal() && (oldest == nil || e.job.CreatedAt.Before(oldest.job.CreatedAt)) {
				oldest = e
			}
		}
		if oldest == nil {
			return model.Job{}, ErrBusy
		}
		if err := m.audit.Append("job_evicted", oldest.job.ID, oldest.job.Principal, string(oldest.job.State)); err != nil {
			m.fail(err)
			return model.Job{}, ErrUnavailable
		}
		if err := m.store.Delete(oldest.job.ID); err != nil {
			m.fail(err)
			return model.Job{}, ErrUnavailable
		}
		delete(m.jobs, oldest.job.ID)
	}
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return model.Job{}, err
	}
	id := hex.EncodeToString(b)
	j := model.Job{ID: id, Principal: principal, State: model.Queued, CreatedAt: time.Now().UTC()}
	if err := m.store.Save(j); err != nil {
		m.fail(err)
		return model.Job{}, ErrUnavailable
	}
	if err := m.audit.Append("job_admitted", id, principal, string(j.State)); err != nil {
		m.fail(err)
		return model.Job{}, ErrUnavailable
	}
	ctx, cancel := context.WithCancel(context.Background())
	e := &entry{job: j, request: r, ctx: ctx, cancel: cancel}
	m.jobs[id] = e
	m.inFlight++
	m.submitted++
	m.queue <- e
	return j, nil
}

func clone(j model.Job) model.Job {
	if j.Result != nil {
		r := *j.Result
		j.Result = &r
	}
	return j
}
func (m *Manager) Get(principal, id string) (model.Job, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.jobs[id]
	if !ok || e.job.Principal != principal {
		return model.Job{}, ErrNotFound
	}
	return clone(e.job), nil
}
func (m *Manager) List(principal string) []model.Job {
	m.mu.Lock()
	defer m.mu.Unlock()
	jobs := []model.Job{}
	for _, e := range m.jobs {
		if e.job.Principal == principal {
			j := clone(e.job)
			j.Result = nil // listings expose bounded metadata; fetch output individually
			jobs = append(jobs, j)
		}
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].CreatedAt.After(jobs[j].CreatedAt) })
	if len(jobs) > 100 {
		jobs = jobs[:100]
	}
	return jobs
}
func (m *Manager) Cancel(principal, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.jobs[id]
	if !ok || e.job.Principal != principal {
		return ErrNotFound
	}
	if e.job.State.Terminal() {
		return nil
	}
	if err := m.audit.Append("job_cancel_requested", id, principal, string(e.job.State)); err != nil {
		m.fail(err)
		return ErrUnavailable
	}
	e.cancel()
	return nil
}
func (m *Manager) Stats() Stats {
	m.mu.Lock()
	defer m.mu.Unlock()
	return Stats{!m.closed && !m.unhealthy, m.inFlight, len(m.jobs), m.submitted, m.completed}
}

// fail is called with m.mu held and immediately cancels all admitted work.
func (m *Manager) fail(err error) {
	m.unhealthy = true
	slog.Error("service quarantined", "error", err)
	for _, e := range m.jobs {
		if e.cancel != nil {
			e.cancel()
		}
	}
}

func (m *Manager) worker() {
	defer m.wg.Done()
	for e := range m.queue {
		m.execute(e)
	}
}
func (m *Manager) execute(e *entry) {
	defer func() {
		m.mu.Lock()
		m.inFlight--
		if e.job.State.Terminal() {
			m.completed++
		}
		e.request = model.Request{}
		e.cancel()
		m.mu.Unlock()
	}()
	m.mu.Lock()
	if e.ctx.Err() != nil || m.unhealthy || m.closed {
		m.finish(e, model.Result{State: model.Cancelled, ExitCode: -1})
		m.mu.Unlock()
		return
	}
	now := time.Now().UTC()
	e.job.StartedAt = &now
	e.job.State = model.Running
	if err := m.audit.Append("job_started", e.job.ID, e.job.Principal, string(e.job.State)); err != nil {
		m.fail(err)
		m.mu.Unlock()
		return
	}
	if err := m.store.Save(e.job); err != nil {
		m.fail(err)
		m.mu.Unlock()
		return
	}
	m.mu.Unlock()
	ctx, cancel := context.WithTimeout(e.ctx, time.Duration(e.request.TimeoutMS)*time.Millisecond)
	defer cancel()
	result, err := m.run(ctx, model.Task{ID: e.job.ID, Request: e.request})
	m.mu.Lock()
	defer m.mu.Unlock()
	if err != nil {
		m.fail(err)
		result = model.Result{State: model.Failed, ExitCode: -1, Error: "execution backend failed; service quarantined"}
	}
	if err == nil && ctx.Err() == context.DeadlineExceeded && result.State != model.OutputLimit {
		result.State = model.TimedOut
	} else if err == nil && e.ctx.Err() != nil && result.State != model.OutputLimit {
		result.State = model.Cancelled
	}
	if !result.State.Terminal() {
		m.fail(errors.New("backend returned nonterminal result"))
		result.State = model.Failed
	}
	m.finish(e, result)
}
func (m *Manager) run(ctx context.Context, task model.Task) (result model.Result, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("backend panic: %v", p)
		}
	}()
	return m.backend.Run(ctx, task)
}

// finish requires the manager mutex. No result becomes visible until persisted.
func (m *Manager) finish(e *entry, r model.Result) {
	j := e.job
	now := time.Now().UTC()
	j.State = r.State
	j.FinishedAt = &now
	j.Result = &r
	if err := m.audit.Append("job_finished", j.ID, j.Principal, string(j.State)); err != nil {
		m.fail(err)
		return
	}
	if err := m.store.Save(j); err != nil {
		m.fail(err)
		return
	}
	e.job = j
}
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		for _, e := range m.jobs {
			if e.cancel != nil {
				e.cancel()
			}
		}
		close(m.queue)
	}
	m.mu.Unlock()
	done := make(chan struct{})
	go func() { m.wg.Wait(); close(done) }()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-done:
		return m.backend.Close()
	}
}
