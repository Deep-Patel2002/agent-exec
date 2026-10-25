#!/usr/bin/env bash
set -euo pipefail
[[ ${WSL_DISTRO_NAME:-} == AgentExecTest && $EUID == 0 ]] || { echo 'Only for the dedicated AgentExecTest WSL environment' >&2; exit 1; }
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
install -d -m 0700 -o agentexec -g agentexec /var/lib/agent-exec-live
if [[ ! -f /var/lib/agent-exec-live/auth/client.token ]]; then
    runuser -u agentexec -- "$repo/bin/agent-exec" init-token -dir /var/lib/agent-exec-live/auth -principal local
fi
python3 - "$repo" <<'PY'
import json, pathlib, sys
p = pathlib.Path(sys.argv[1])
c = json.loads((p/'configs/config.example.json').read_text())
c.update(state_dir='/var/lib/agent-exec-live', rootfs='/opt/agent-exec/rootfs-v2',
         seccomp_path='/opt/agent-exec/default-v2.bpf', tokens_file='/var/lib/agent-exec-live/auth/tokens.json')
(pathlib.Path('/var/lib/agent-exec-live')/'config.json').write_text(json.dumps(c,indent=2)+'\n')
PY
chown agentexec:agentexec /var/lib/agent-exec-live/config.json
chmod 0600 /var/lib/agent-exec-live/config.json
systemd-run --unit=agentexec-demo --collect --uid=agentexec --property=Delegate=yes \
    --property=KillMode=control-group --property=Restart=on-failure --property=RestartSec=1 \
    --working-directory="$repo" "$repo/bin/agent-exec-server" -config /var/lib/agent-exec-live/config.json
