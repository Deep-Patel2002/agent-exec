package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"agentexec/internal/durable"
	"agentexec/internal/model"
	"agentexec/internal/strictjson"
)

type Store struct {
	dir string
	max int
}

var jobID = regexp.MustCompile(`^[a-f0-9]{32}$`)

func ValidID(id string) bool { return jobID.MatchString(id) }

func New(dir string, max int) (*Store, error) {
	if max < 1 || max > 10000 {
		return nil, errors.New("retained job limit must be 1-10000")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return &Store{dir, max}, nil
}
func (s *Store) Save(j model.Job) error {
	if !ValidID(j.ID) {
		return errors.New("invalid job ID")
	}
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	return durable.Write(filepath.Join(s.dir, j.ID+".json"), append(data, '\n'))
}
func (s *Store) Delete(id string) error {
	if !ValidID(id) {
		return errors.New("invalid job ID")
	}
	if err := os.Remove(filepath.Join(s.dir, id+".json")); err != nil {
		return err
	}
	return durable.SyncDir(s.dir)
}
func (s *Store) Load() ([]model.Job, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var jobs []model.Job
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".pending-") {
			continue
		}
		if !strings.HasSuffix(entry.Name(), ".json") {
			return nil, errors.New("unexpected file in job store")
		}
		if len(jobs) >= s.max {
			return nil, errors.New("job store exceeds configured retention bound")
		}
		id := strings.TrimSuffix(entry.Name(), ".json")
		if !ValidID(id) {
			return nil, errors.New("invalid record filename")
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Size() > 8<<20 {
			return nil, errors.New("invalid or oversized job record")
		}
		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var j model.Job
		if err := strictjson.Decode(data, &j); err != nil {
			return nil, fmt.Errorf("corrupt job record %s: %w", id, err)
		}
		if j.ID != id || j.Principal == "" {
			return nil, errors.New("job record identity mismatch")
		}
		jobs = append(jobs, j)
	}
	return jobs, nil
}
