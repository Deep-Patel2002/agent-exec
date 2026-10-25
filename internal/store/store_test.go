package store

import (
	"agentexec/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func TestPersistenceAndCorruption(t *testing.T) {
	dir := t.TempDir()
	s, _ := New(dir, 8)
	j := model.Job{ID: "12345678901234567890123456789012", Principal: "alice", State: model.Queued}
	if err := s.Save(j); err != nil {
		t.Fatal(err)
	}
	j.State = model.Running
	if err := s.Save(j); err != nil {
		t.Fatal(err)
	}
	jobs, err := s.Load()
	if err != nil || len(jobs) != 1 || jobs[0].State != model.Running {
		t.Fatalf("%v %v", jobs, err)
	}
	os.WriteFile(filepath.Join(dir, j.ID+".json"), []byte("broken"), 0600)
	if _, err := s.Load(); err == nil {
		t.Fatal("accepted corruption")
	}
}
func TestRejectTraversal(t *testing.T) {
	s, _ := New(t.TempDir(), 8)
	if err := s.Save(model.Job{ID: "../escape"}); err == nil {
		t.Fatal("accepted path escape")
	}
}
