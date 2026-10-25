package policy

import (
	"errors"
	"fmt"
	"path"
	"regexp"
	"strings"

	"agentexec/internal/model"
)

type Policy struct {
	AllowedExecutables []string `json:"allowed_executables"`
	DefaultTimeoutMS   int64    `json:"default_timeout_ms"`
	MaxTimeoutMS       int64    `json:"max_timeout_ms"`
	MemoryBytes        int64    `json:"memory_bytes"`
	PidsMax            int      `json:"pids_max"`
	CPUMillis          int      `json:"cpu_millis"`
	OutputBytes        int      `json:"output_bytes"`
	MaxInputBytes      int      `json:"max_input_bytes"`
	MaxFiles           int      `json:"max_files"`
}

func Default() Policy {
	return Policy{
		AllowedExecutables: []string{"/usr/bin/python3", "/bin/sh"},
		DefaultTimeoutMS:   10000, MaxTimeoutMS: 30000,
		MemoryBytes: 256 << 20, PidsMax: 64, CPUMillis: 1000,
		OutputBytes: 65536, MaxInputBytes: 262144, MaxFiles: 32,
	}
}

func (p Policy) Validate() error {
	if len(p.AllowedExecutables) == 0 || len(p.AllowedExecutables) > 32 {
		return errors.New("require 1-32 allowed executables")
	}
	for _, s := range p.AllowedExecutables {
		if !path.IsAbs(s) || path.Clean(s) != s || strings.ContainsAny(s, "\x00\\") {
			return errors.New("executable paths must be clean absolute sandbox paths")
		}
	}
	if p.DefaultTimeoutMS < 100 || p.DefaultTimeoutMS > p.MaxTimeoutMS || p.MaxTimeoutMS > 300000 {
		return errors.New("timeouts must be between 100 and 300000 ms")
	}
	if p.MemoryBytes < 64<<20 || p.MemoryBytes > 4<<30 {
		return errors.New("memory must be between 64 MiB and 4 GiB")
	}
	if p.PidsMax < 8 || p.PidsMax > 512 || p.CPUMillis < 10 || p.CPUMillis > 8000 {
		return errors.New("invalid CPU or process limit")
	}
	if p.OutputBytes < 1024 || p.OutputBytes > 1<<20 || p.MaxInputBytes < 1 || p.MaxInputBytes > 1<<20 || p.MaxFiles < 1 || p.MaxFiles > 128 {
		return errors.New("invalid input or output limits")
	}
	return nil
}

var fileName = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]{0,199}$`)

func ValidFileName(s string) bool {
	if !fileName.MatchString(s) || path.Clean(s) != s || strings.HasSuffix(s, "/") {
		return false
	}
	for _, part := range strings.Split(s, "/") {
		if part == ".." || part == "." || len(part) > 80 {
			return false
		}
	}
	return true
}

// Normalize copies request data so callers cannot mutate admitted work.
func (p Policy) Normalize(r model.Request) (model.Request, error) {
	if len(r.Argv) < 1 || len(r.Argv) > 64 {
		return r, errors.New("argv must contain 1-64 arguments")
	}
	allowed := false
	for _, s := range p.AllowedExecutables {
		if r.Argv[0] == s {
			allowed = true
		}
	}
	if !allowed {
		return r, errors.New("executable is not permitted by server policy")
	}
	argBytes := 0
	for _, s := range r.Argv {
		argBytes += len(s)
		if strings.ContainsRune(s, 0) {
			return r, errors.New("arguments must not contain NUL")
		}
	}
	if argBytes > 32768 {
		return r, errors.New("arguments exceed 32 KiB")
	}
	if r.TimeoutMS == 0 {
		r.TimeoutMS = p.DefaultTimeoutMS
	}
	if r.TimeoutMS < 100 || r.TimeoutMS > p.MaxTimeoutMS {
		return r, fmt.Errorf("timeout must be between 100 and %d ms", p.MaxTimeoutMS)
	}
	if len(r.Files) > p.MaxFiles {
		return r, errors.New("too many input files")
	}
	total := 0
	names := make(map[string]bool)
	files := make(map[string]string, len(r.Files))
	for name, content := range r.Files {
		if !ValidFileName(name) {
			return r, errors.New("input filename must be a clean relative portable path")
		}
		lower := strings.ToLower(name)
		if names[lower] {
			return r, errors.New("case-insensitive input filename collision")
		}
		names[lower] = true
		total += len(content)
		if total > p.MaxInputBytes {
			return r, errors.New("input files exceed byte limit")
		}
		files[name] = content
	}
	for name := range names {
		for parent := path.Dir(name); parent != "."; parent = path.Dir(parent) {
			if names[parent] {
				return r, errors.New("input file and directory paths conflict")
			}
		}
	}
	r.Argv = append([]string(nil), r.Argv...)
	r.Files = files
	return r, nil
}
