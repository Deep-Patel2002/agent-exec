# Deployment and operations

## Supported execution host

Use a dedicated Ubuntu 24.04+ VM or comparable Linux system with:

- Linux 5.14+ with `clone3(CLONE_INTO_CGROUP)`, `cgroup.kill`, seccomp, and user
  namespaces. The actual readiness probe is authoritative; version alone is not.
- A unified cgroup v2 mount and delegatable `cpu`, `memory`, and `pids`
  controllers, including `memory.swap.max` and `memory.oom.group`.
- systemd supporting controller delegation and a dedicated unprivileged user.
- Non-setuid bubblewrap 0.9+, Python 3, compiler, and libseccomp development files.
- A supported Go toolchain to build the binaries (tested Go 1.27.3).

Do not globally disable host security modules to make a probe pass. If a host
policy prohibits required namespaces, use an appropriately configured dedicated
VM or an administrator-reviewed policy exception for this service.

### Ubuntu AppArmor namespace policy

Ubuntu 24.04 can enable `kernel.apparmor_restrict_unprivileged_userns=1`.
Without an appropriate bubblewrap profile, setup can fail with
`bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`, before the
workload starts. Review Ubuntu's packaged `bwrap-userns-restrict` profile and
existing host policy before enabling it on the dedicated execution VM:

```sh
sudo apt-get install -y apparmor-profiles
if [ ! -e /etc/apparmor.d/bwrap-userns-restrict ]; then
  sudo install -m 0644 /usr/share/apparmor/extra-profiles/bwrap-userns-restrict \
    /etc/apparmor.d/bwrap-userns-restrict
fi
sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict
```

The packaged profile attaches to the system `/usr/bin/bwrap`, so review its
effect on any other bubblewrap users on that VM. The installer does not change
host AppArmor policy automatically. Keep the global namespace restriction and
AppArmor enabled; repeat the real isolation tests after any policy change.
CI loads this distro profile on its disposable Ubuntu runner before testing.
See [Ubuntu's AppArmor documentation](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/)
and the [upstream bubblewrap profile](https://gitlab.com/apparmor/apparmor/-/blob/master/profiles/apparmor/profiles/extras/bwrap-userns-restrict).

## Install

Run from the repository on the Linux execution host:

```sh
sudo apt-get update
sudo apt-get install -y bubblewrap libseccomp-dev gcc make python3
make build seccomp
sudo bash tools/install-local.sh
sudo systemctl start agent-exec.service
sudo journalctl -u agent-exec.service -n 30 --no-pager
```

`make seccomp` refuses to overwrite an existing filter. Generate a new artifact
name or remove only your obsolete generated `bin/default.bpf` before rebuilding.
The installer preserves existing configuration, credentials, and rootfs; it does
not silently overwrite those operator decisions. It refuses to replace runtime
artifacts while the installed service is active.

Artifacts live under `/opt/agent-exec`; configuration and hashed credentials under
`/etc/agent-exec`; private state under `/var/lib/agent-exec`. The sample service
binds only `127.0.0.1:8080`. Do not broaden the bind address or expose it through
an unauthenticated tunnel. Remote TLS/identity gateway integration is outside
this release's scope.

The server self-tests the real backend before listening. It refuses root
execution, missing controllers, invalid image/filter paths, and an unsandboxed
fallback. Root is used only by setup to install artifacts and delegate resources.

The unit denies the kernel `syslog` syscall directly instead of enabling
`ProtectKernelLogs`, whose `/proc/kmsg` overmount can prevent bubblewrap from
mounting the guest procfs on newer kernels. The service runs without capabilities,
uses private devices, and the guest seccomp policy also denies `syslog`.
The installed-service verification checks that kernel logs cannot be read through
the syscall or `/proc/kmsg`, and that `/dev/kmsg` is absent from the guest.

## Verify the installed service

```sh
sudo python3 tools/verify-service.py \
  --token-file /var/lib/agent-exec/auth/client.token \
  --benchmark 30 --report .local/verification/service.json

sudo systemctl show agent-exec.service -p MainPID -p ControlGroup -p MemoryCurrent
```

The script does not print credentials or retry submissions. It polls readiness
and reads job state; each actual submission happens once. Benchmark the workload
you intend to run, not only the included tiny Python example.

## Credentials and ownership

`agent-exec init-token -dir PRIVATE_DIRECTORY -principal NAME` creates a random
client token and server-side hash database, both with mode 0600. It refuses to
overwrite files. Each configured principal can fetch/cancel only its own jobs;
unknown and foreign IDs both return 404. Multiple credentials may map to a
principal, supporting a planned rotation period.

For rotation, generate new credentials in a new private directory, add the new
digest to the server database, atomically install the revised database with mode
0600, and restart. Switch clients, remove the old digest, and restart again.
The service loads credentials only at startup. Plain secrets never belong in
argv, a checked-in example, a post, or operational logs.

## Quarantine and recovery

`/livez` reports process liveness and is unauthenticated. `/readyz` and `/metrics`
require a bearer token. A persistence, audit, backend, or cleanup failure makes
readiness return 503, cancels admitted work, and rejects new submissions. Check
the journal and underlying storage/runtime before restarting.

On startup, the backend kills/removes stale `job-<id>` cgroups and deletes stale
private workspace directories. The manager then marks persisted queued/running
records `interrupted`, preserving completed results. No jobs are replayed. The
systemd unit uses `KillMode=control-group`, so crash/restart handling also covers
descendants if the supervisor cannot run cleanup.

Exercise this deliberately on a test host:

```sh
sudo python3 tools/verify-service.py --token-file /var/lib/agent-exec/auth/client.token \
  --restart-phase before
sudo systemctl kill --signal=KILL --kill-whom=main agent-exec.service
sudo python3 tools/verify-service.py --token-file /var/lib/agent-exec/auth/client.token \
  --restart-phase after
```

## Audit and data retention

Audit events contain sequence/hash links, timestamp, event kind, job ID,
principal, and state. They deliberately exclude submitted code, arguments,
credentials, and output. Private result files still contain job output; handle
state/backup access accordingly. Terminal records are evicted oldest-first when
the retained-record count is reached. Active jobs are not evicted.

The audit log is capped at 128 MiB and never truncated automatically. Alert well
before the cap (for example 96 MiB). Stop admission, stop the service, archive
the complete log to an independently protected location and record its final
hash, then move it out of the active path and restart with a new chain. Keep
that archive/chain boundary in your operations record. Do not edit a corrupt
chain merely to make startup pass; preserve it for investigation.

## Monitoring

Track authenticated readiness, `agentexec_in_flight`, retained-record count,
submitted/completed totals, request errors, audit size, disk free space, and the
service cgroup's CPU/memory/task pressure. Process-lifetime counters reset after
a restart. There is no per-user billing or high-availability control plane.

## Upgrade and rollback

1. Build/test a new binary, rootfs, and native seccomp artifact on a test host.
2. Preserve configuration, hash database, private records, audit, and old runtime
   artifacts. Inspect `.source-packages.txt` and the image SHA-256 manifest.
3. Drain/cancel work and stop the service. Install the new versioned artifacts
   and update rootfs/filter paths in configuration.
4. Start and run readiness, isolation, and application checks. Roll back the
   artifact paths/binaries if they fail. Never replay interrupted jobs implicitly.

The rootfs builder captures installed distro package versions; it is reproducible
from those package inputs, not a guarantee of bit-for-bit future rebuilds from
an unpinned package mirror. Provisioning pinned package repositories and image
signing is additional release-infrastructure work.
