# Verification evidence

Local verification date: **2026-10-25, America/Los_Angeles**.

## Environment

Windows host with a dedicated `AgentExecTest` WSL2 Ubuntu 24.04 environment;
Linux `5.15.167.4-microsoft-standard-WSL2`, amd64, glibc 2.39; Go 1.27.3;
bubblewrap 0.9.0. Execution ran as an unprivileged account under systemd cgroup
delegation. Root was used for fixture/artifact installation, not submitted jobs.

The cgroup-v2 configuration, runtime image, native BPF program, actual
`CLONE_INTO_CGROUP` spawn, and syscall policy were exercised rather than mocked
for isolation checks. Cross-platform control-plane tests use a fake backend to
test lifecycle and fault handling; those are distinct from the Linux tests.

## Checks run

| Check | Result |
|---|---|
| Windows `go test -count=1 ./...` | Passed |
| Linux `go test -count=1 ./...` | Passed |
| Linux `go test -race -count=1 ./...` | Passed |
| Go vet and gofmt check | Passed |
| Native C filter build with `-Wall -Wextra -Werror` | Passed |
| Explicit Linux integration suite | Passed: 14 workload/boundary/resource scenarios, plus capture-budget test |
| Real HTTP service verification | Passed: 12 checks |
| Installed hardened systemd unit | Passed: same 12 HTTP checks |
| Forced SIGKILL and restart of installed service | Passed: running job recovered as interrupted, not replayed |
| Filename-policy fuzzing, 10 seconds | Passed: 1,637,217 executions, no failing input |
| Strict-JSON fuzzing, approximately 11 seconds | Passed: 386,549 executions, no failing input |
| `govulncheck` v1.9.0, checked 2026-10-25 | Reported no vulnerabilities for the Go program/dependencies |

The scan does not audit C code, libseccomp, bubblewrap, the distro rootfs,
hypervisor, or kernel. Fuzz smoke tests are bounded local observations and do
not prove parser correctness. The GitHub Actions workflow is provided; no claim
is made that a remote GitHub run happened during this local build.

The Linux scenarios cover legitimate execution, absent host files, clean host
environment, read-only rootfs and inputs, denied sockets, denied nested
namespace creation, active seccomp/no-new-privileges, writable ephemeral
directories, output overflow, deadline/detached-child cleanup, memory exhaustion,
process exhaustion, and CPU-bandwidth limits. Tests assert no leaked job
cgroups/workspaces after completion.

## Measured benchmark

The committed [raw service report](verification/2026-10-25/service.json) contains
all samples. Thirty sequential warm-cache executions of
`print(sum(range(100)))` through the installed service measured:

| Observation | Result |
|---|---:|
| Sandbox execution median | 16 ms |
| Sandbox execution p95 | 37 ms |
| Trusted host Python baseline median | 11.507 ms |
| HTTP submit-to-terminal p95 | 140.149 ms |

Sandbox execution time is the backend wall counter; end-to-end time additionally
includes durable admission/completion, API calls, scheduling, and client polling.
The baseline is a fixed trusted command on the same Linux VM, not execution of
untrusted input outside containment. The first baseline/sandbox cache conditions
are not guaranteed identical. No p99, capacity, cold-image, high-concurrency, or
production-SLO conclusion follows from these 30 samples.

An [earlier 30-run sample](verification/2026-10-25/service-initial.json) measured
14 ms median and 18 ms p95 sandbox execution. This was a shared development
machine with other build/test activity during verification; the difference is
not a controlled comparison or evidence of a causal performance improvement.
The table above preserves the later measurement rather than selecting the
fastest observed run.

The older kernel does not expose `memory.peak`; the optional result field is
absent. The implementation does not substitute memory.current or invent a peak.

Additional evidence:

- [Installed-unit checks](verification/2026-10-25/installed-unit.json)
- [Crash/restart record](verification/2026-10-25/restart.json)

Reports contain synthetic test outcomes and timings, not credentials, code from
users, private output, or a copy of the runtime state directory.

## Remaining assurance work

Run representative sustained/concurrent workloads, test on the intended
production kernel/hypervisor, independently review the code and seccomp policy,
scan/pin/sign runtime image inputs, establish patch and audit-export procedures,
and obtain real operational feedback before broadening deployment. Arm64/Mac
clients can be cross-built; runtime containment still needs a separately tested
native Linux arm64 guest/filter.
