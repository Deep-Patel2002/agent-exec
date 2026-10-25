package model

import "time"

type State string

const (
	Queued            State = "queued"
	Running           State = "running"
	Succeeded         State = "succeeded"
	Failed            State = "failed"
	TimedOut          State = "timed_out"
	Cancelled         State = "cancelled"
	OutputLimit       State = "output_limit"
	ResourceExhausted State = "resource_exhausted"
	Interrupted       State = "interrupted"
)

func (s State) Terminal() bool { return s != Queued && s != Running }

type Request struct {
	Argv      []string          `json:"argv"`
	Files     map[string]string `json:"files,omitempty"`
	TimeoutMS int64             `json:"timeout_ms,omitempty"`
}

type Usage struct {
	WallMS          int64   `json:"wall_ms"`
	CPUUsec         uint64  `json:"cpu_usec"`
	MemoryPeakBytes *uint64 `json:"memory_peak_bytes,omitempty"`
	OOMKills        uint64  `json:"oom_kills"`
	PidsLimitHits   uint64  `json:"pids_limit_hits"`
}

type Result struct {
	State           State  `json:"state"`
	ExitCode        int    `json:"exit_code"`
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	OutputTruncated bool   `json:"output_truncated"`
	Usage           Usage  `json:"usage"`
	Error           string `json:"error,omitempty"`
}

type Job struct {
	ID         string     `json:"id"`
	Principal  string     `json:"principal"`
	State      State      `json:"state"`
	CreatedAt  time.Time  `json:"created_at"`
	StartedAt  *time.Time `json:"started_at,omitempty"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
	Result     *Result    `json:"result,omitempty"`
}

type Task struct {
	ID      string
	Request Request
}
