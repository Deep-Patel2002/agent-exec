//go:build !linux

package sandbox

import (
	"agentexec/internal/model"
	"agentexec/internal/policy"
	"context"
	"errors"
)

type Options struct {
	RootFS, CgroupRoot, WorkspaceRoot, BwrapPath, SeccompPath string
	Policy                                                    policy.Policy
}
type Linux struct{}

func NewLinux(Options) (*Linux, error) {
	return nil, errors.New("execution requires Linux; use a Linux VM, not an unsandboxed fallback")
}
func (*Linux) Run(context.Context, model.Task) (model.Result, error) {
	return model.Result{}, errors.New("unsupported operating system")
}
func (*Linux) Close() error { return nil }
