package sandbox

import (
	"context"
	"sync"

	"agentexec/internal/model"
)

type Backend interface {
	Run(context.Context, model.Task) (model.Result, error)
	Close() error
}

// Capture shares a byte budget between stdout and stderr. Once exhausted it
// cancels execution but continues acknowledging writes to avoid pipe deadlocks.
type Capture struct {
	mu        sync.Mutex
	limit     int
	used      int
	stdout    []byte
	stderr    []byte
	truncated bool
	cancel    context.CancelFunc
}
type captureWriter struct {
	capture *Capture
	stderr  bool
}

func NewCapture(limit int, cancel context.CancelFunc) *Capture {
	return &Capture{limit: limit, cancel: cancel}
}
func (c *Capture) Stdout() *captureWriter { return &captureWriter{capture: c} }
func (c *Capture) Stderr() *captureWriter { return &captureWriter{capture: c, stderr: true} }
func (w *captureWriter) Write(p []byte) (int, error) {
	c := w.capture
	c.mu.Lock()
	defer c.mu.Unlock()
	n := len(p)
	keep := min(n, c.limit-c.used)
	if w.stderr {
		c.stderr = append(c.stderr, p[:keep]...)
	} else {
		c.stdout = append(c.stdout, p[:keep]...)
	}
	c.used += keep
	if keep < n && !c.truncated {
		c.truncated = true
		c.cancel()
	}
	return n, nil
}
func (c *Capture) Snapshot() (string, string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return string(c.stdout), string(c.stderr), c.truncated
}
