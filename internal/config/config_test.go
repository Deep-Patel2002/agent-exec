package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"agentexec/internal/policy"
)

func TestOnlyExplicitLoopbackListeners(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		address string
		valid   bool
	}{{"127.0.0.1:8080", true}, {"[::1]:8080", true}, {"0.0.0.0:8080", false}, {"localhost:8080", false}, {":8080", false}, {"192.168.1.2:8080", false}} {
		c := Config{Listen: tc.address, StateDir: dir, RootFS: filepath.Join(dir, "rootfs"), CgroupRoot: "auto", BwrapPath: filepath.Join(dir, "bwrap"), SeccompPath: filepath.Join(dir, "filter"), TokensFile: filepath.Join(dir, "tokens"), Workers: 1, MaxInFlight: 2, RetainedJobs: 8, Policy: policy.Default()}
		data, _ := json.Marshal(c)
		path := filepath.Join(dir, "config.json")
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		_, err := Load(path)
		if (err == nil) != tc.valid {
			t.Errorf("%s: %v", tc.address, err)
		}
	}
}
