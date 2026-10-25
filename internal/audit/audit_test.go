package audit

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestChainAndConcurrentAppends(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Append("event", "job", "principal", "running"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	l, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if l.sequence != 20 {
		t.Fatal(l.sequence)
	}
	l.Close()
	data, _ := os.ReadFile(path)
	data[15] ^= 1
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if l, err := Open(path); err == nil {
		l.Close()
		t.Fatal("accepted corrupt chain")
	}
}
func TestRejectTruncatedTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, _ := Open(path)
	l.Append("x", "", "", "")
	l.Close()
	data, _ := os.ReadFile(path)
	os.WriteFile(path, data[:len(data)-1], 0600)
	if l, err := Open(path); err == nil {
		l.Close()
		t.Fatal("accepted incomplete line")
	}
}

func TestSizeLimitFailsClosed(t *testing.T) {
	l, err := Open(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.bytes = MaxLogBytes
	if err := l.Append("event", "", "", ""); err == nil {
		t.Fatal("accepted event past audit budget")
	}
	if l.sequence != 0 || l.failed == nil {
		t.Fatal("audit did not preserve failure state")
	}
}
