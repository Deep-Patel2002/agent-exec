package config

import (
	"errors"
	"net"
	"os"
	"path/filepath"

	"agentexec/internal/policy"
	"agentexec/internal/strictjson"
)

type Config struct {
	Listen       string        `json:"listen"`
	StateDir     string        `json:"state_dir"`
	RootFS       string        `json:"rootfs"`
	CgroupRoot   string        `json:"cgroup_root"`
	BwrapPath    string        `json:"bwrap_path"`
	SeccompPath  string        `json:"seccomp_path"`
	TokensFile   string        `json:"tokens_file"`
	Workers      int           `json:"workers"`
	MaxInFlight  int           `json:"max_in_flight"`
	RetainedJobs int           `json:"retained_jobs"`
	Policy       policy.Policy `json:"policy"`
}

func Load(path string) (Config, error) {
	var c Config
	info, err := os.Stat(path)
	if err != nil {
		return c, err
	}
	if info.Size() > 65536 {
		return c, errors.New("configuration too large")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := strictjson.Decode(data, &c); err != nil {
		return c, err
	}
	host, port, err := net.SplitHostPort(c.Listen)
	if err != nil || port == "" {
		return c, errors.New("listen must be an explicit loopback IP and port")
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return c, errors.New("only loopback listeners are supported; use an authenticated TLS gateway for remote clients")
	}
	for _, p := range []string{c.StateDir, c.RootFS, c.BwrapPath, c.SeccompPath, c.TokensFile} {
		if !filepath.IsAbs(p) || filepath.Clean(p) != p {
			return c, errors.New("configuration paths must be clean absolute paths")
		}
	}
	if c.Workers < 1 || c.Workers > 32 || c.MaxInFlight < c.Workers || c.MaxInFlight > 256 || c.RetainedJobs < c.MaxInFlight || c.RetainedJobs > 10000 {
		return c, errors.New("invalid admission or retention settings")
	}
	return c, c.Policy.Validate()
}
