// Package audit maintains a synchronously flushed hash-chained event log.
// The chain detects accidental corruption and partial edits, not a privileged
// attacker who can rewrite the complete log. Export events to an independent sink.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"
)

type Event struct {
	Sequence     uint64    `json:"sequence"`
	Time         time.Time `json:"time"`
	Kind         string    `json:"kind"`
	JobID        string    `json:"job_id,omitempty"`
	Principal    string    `json:"principal,omitempty"`
	State        string    `json:"state,omitempty"`
	PreviousHash string    `json:"previous_hash"`
	Hash         string    `json:"hash,omitempty"`
}
type Log struct {
	mu       sync.Mutex
	file     *os.File
	sequence uint64
	previous string
	failed   error
	bytes    int64
}

const MaxLogBytes = 128 << 20

func digest(e Event) string {
	e.Hash = ""
	data, _ := json.Marshal(e)
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	l := &Log{file: f}
	initial, err := f.Stat()
	if err != nil || !initial.Mode().IsRegular() || initial.Size() > MaxLogBytes {
		f.Close()
		return nil, errors.New("audit log is invalid or exceeds 128 MiB; archive offline")
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 65536)
	var end int64
	for scanner.Scan() {
		var e Event
		if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
			f.Close()
			return nil, errors.New("corrupt audit record")
		}
		if e.Sequence != l.sequence+1 || e.PreviousHash != l.previous || e.Hash != digest(e) {
			f.Close()
			return nil, errors.New("audit chain verification failed")
		}
		l.sequence, l.previous = e.Sequence, e.Hash
		end += int64(len(scanner.Bytes()) + 1)
	}
	if err := scanner.Err(); err != nil {
		f.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if info.Size() != end {
		f.Close()
		return nil, errors.New("audit log has an incomplete final record")
	}
	l.bytes = end
	return l, nil
}

func (l *Log) Append(kind, id, principal, state string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.failed != nil {
		return l.failed
	}
	e := Event{Sequence: l.sequence + 1, Time: time.Now().UTC(), Kind: kind, JobID: id, Principal: principal, State: state, PreviousHash: l.previous}
	e.Hash = digest(e)
	data, err := json.Marshal(e)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if l.bytes+int64(len(data)) > MaxLogBytes {
		l.failed = errors.New("audit log reached 128 MiB; archive offline before restarting")
		return l.failed
	}
	n, err := l.file.Write(data)
	if err == nil && n != len(data) {
		err = errors.New("short audit write")
	}
	if err == nil {
		err = l.file.Sync()
	}
	if err != nil {
		l.failed = fmt.Errorf("audit persistence failed: %w", err)
		return l.failed
	}
	l.sequence, l.previous = e.Sequence, e.Hash
	l.bytes += int64(len(data))
	return nil
}
func (l *Log) Close() error { l.mu.Lock(); defer l.mu.Unlock(); return l.file.Close() }
