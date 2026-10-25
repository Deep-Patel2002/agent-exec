#!/usr/bin/env bash
# Isolated development harness; never run this on a general-purpose host.
set -euo pipefail
[[ "${WSL_DISTRO_NAME:-}" == AgentExecTest ]] || { echo 'Requires the isolated AgentExecTest WSL distribution' >&2; exit 1; }
[[ $EUID == 0 ]] || { echo 'Requires root inside the test distribution' >&2; exit 1; }
if [[ ! -x /opt/go/bin/go ]]; then
    curl -fLsS https://go.dev/dl/go1.27.3.linux-amd64.tar.gz -o /tmp/agentexec-go.tar.gz
    printf '%s  %s\n' 65efbc80fdc1fa2cd2631cad5b481777a68e8725f34e89f50fc6ac714e379b40 /tmp/agentexec-go.tar.gz | sha256sum -c -
    tar -xzf /tmp/agentexec-go.tar.gz -C /opt
fi
# Configure cgroup v2 at WSL boot; this helper never modifies kernel defaults.
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || {
    echo 'Enable systemd + unified cgroup v2 at WSL boot; see docs/DEVELOPMENT.md' >&2
    exit 1
}
printf '+cpu +memory +pids' > /sys/fs/cgroup/cgroup.subtree_control
if ! id agentexec >/dev/null 2>&1; then useradd -m -s /bin/bash agentexec; fi
/opt/go/bin/go version
cat /sys/fs/cgroup/cgroup.controllers
