#!/usr/bin/env bash
# Installs a built release on a dedicated Ubuntu 24.04+ systemd host.
set -euo pipefail
[[ $EUID == 0 ]] || { echo 'Run with sudo' >&2; exit 1; }
[[ $(stat -fc %T /sys/fs/cgroup) == cgroup2fs ]] || { echo 'Unified cgroup v2 required' >&2; exit 1; }
repo=$(cd -- "$(dirname -- "$0")/.." && pwd)
for file in bin/agent-exec bin/agent-exec-server bin/default.bpf; do
    [[ -f "$repo/$file" ]] || { echo "Missing build artifact $file; run make build seccomp" >&2; exit 1; }
done
id agentexec >/dev/null 2>&1 || useradd --system --home-dir /var/lib/agent-exec --shell /usr/sbin/nologin agentexec
install -d -m 0755 /opt/agent-exec/bin /etc/agent-exec
install -d -m 0700 -o agentexec -g agentexec /var/lib/agent-exec
if systemctl is-active --quiet agent-exec.service; then
    echo 'Stop the existing service before replacing runtime artifacts' >&2; exit 1
fi
install -m 0555 "$repo/bin/agent-exec" "$repo/bin/agent-exec-server" /opt/agent-exec/bin/
install -m 0444 "$repo/bin/default.bpf" /opt/agent-exec/default.bpf
if [[ ! -e /opt/agent-exec/rootfs ]]; then bash "$repo/tools/build-rootfs.sh" /opt/agent-exec/rootfs; fi
if [[ ! -e /etc/agent-exec/config.json ]]; then install -m 0644 "$repo/configs/config.example.json" /etc/agent-exec/config.json; fi
if [[ ! -e /etc/agent-exec/tokens.json ]]; then
    runuser -u agentexec -- /opt/agent-exec/bin/agent-exec init-token -dir /var/lib/agent-exec/auth -principal local
    install -m 0600 -o agentexec -g agentexec /var/lib/agent-exec/auth/tokens.json /etc/agent-exec/tokens.json
fi
install -m 0644 "$repo/deploy/agent-exec.service" /etc/systemd/system/agent-exec.service
systemctl daemon-reload
echo 'Installed. Start explicitly: systemctl start agent-exec.service'
echo 'Client credential: /var/lib/agent-exec/auth/client.token (not printed)'
