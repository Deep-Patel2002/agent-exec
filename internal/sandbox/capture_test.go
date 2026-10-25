package sandbox

import (
	"context"
	"sync"
	"testing"
)

func TestCombinedOutputBudget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := NewCapture(100, cancel)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); c.Stdout().Write(make([]byte, 19)); c.Stderr().Write(make([]byte, 19)) }()
	}
	wg.Wait()
	out, errout, truncated := c.Snapshot()
	if len(out)+len(errout) != 100 || !truncated || ctx.Err() == nil {
		t.Fatal("combined output limit not enforced")
	}
}
