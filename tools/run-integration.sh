#!/usr/bin/env bash
# Runs as an unprivileged account inside a delegated systemd service cgroup.
set -euo pipefail
[[ $EUID != 0 ]] || { echo 'Integration tests must run unprivileged' >&2; exit 1; }
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || { echo 'cgroup v2 required' >&2; exit 1; }
export AGENTEXEC_CGROUP_ROOT="/sys/fs/cgroup$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)"
mkdir -p "$AGENTEXEC_CGROUP_ROOT/supervisor"
printf '%s' "$$" > "$AGENTEXEC_CGROUP_ROOT/supervisor/cgroup.procs"
printf '+cpu +memory +pids' > "$AGENTEXEC_CGROUP_ROOT/cgroup.subtree_control"
export AGENTEXEC_ROOTFS=${AGENTEXEC_ROOTFS:-/opt/agent-exec/rootfs}
export AGENTEXEC_SECCOMP=${AGENTEXEC_SECCOMP:-/opt/agent-exec/default.bpf}
export AGENTEXEC_TEST_STATE=${AGENTEXEC_TEST_STATE:-/var/lib/agent-exec-test}
if [[ ${AGENTEXEC_TRACE:-0} == 1 ]]; then
    exec strace -f -o "$AGENTEXEC_TEST_STATE/syscalls.log" go test -tags integration -count=1 -timeout=120s -v ./internal/sandbox "$@"
fi
go test -tags integration -count=1 -timeout=120s -v ./internal/sandbox "$@"
