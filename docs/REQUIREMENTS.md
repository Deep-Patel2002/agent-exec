# Requirements and scope

## Problem and users

An authenticated local agent controller needs to execute generated code without
granting it the controller's files, credentials, network access, or unlimited
resources. The operator must be able to explain what ran, cancel it, recover
after a crash, and measure the cost of containment.

The operator controls the machine, configuration, runtime image, credentials,
and deployment. Callers submit potentially hostile code. The service does not
interpret natural-language permissions or trust an LLM to authorize execution.

## Initial release boundaries

Included: a single-host asynchronous API, Python/shell image, ephemeral files,
zero network access, bounded resources, durable metadata/results, audit events,
metrics, tests, operational scripts, and benchmark evidence.

Excluded: remote public access/TLS termination, web UI, Kubernetes orchestration,
microVMs, GPU access, secret injection, outbound allowlists, durable artifact
export, language/package installation, automatic job replay, distributed queues,
per-tenant fairness/billing, and kernel-exploit resistance. Credentials identify
principals for result ownership; this is not an independently isolated host per
tenant.

## Acceptance matrix

| ID | Requirement | Implementation / verification |
|---|---|---|
| R01 | Authenticate every job and metadata operation | `internal/api`; authentication HTTP tests and real service verification |
| R02 | Caller identity comes from credentials, never request JSON | hashed token database, no request principal field, ownership tests |
| R03 | Reject unknown/duplicate fields, unsafe paths, and oversized inputs | `strictjson`, `policy`; regression and fuzz tests |
| R04 | Mount only the operator-built image and this job's inputs | backend argument construction; real host-file and read-only tests |
| R05 | Prevent host network use | new network namespace plus denied network syscalls; real socket-denial test |
| R06 | Do not propagate host environment or extra application descriptors | cleared launcher/guest environment; real canary test; filter FD consumed by bubblewrap |
| R07 | Place processes in their limited cgroup before execution | `UseCgroupFD`, mandatory clone3; no post-spawn migration fallback |
| R08 | Enforce memory, swap, CPU bandwidth, and process bounds | mandatory cgroup v2 controllers; real OOM, CPU, and fork-limit tests |
| R09 | Bound output and execution time | shared capture budget, job contexts, real flood and timeout tests |
| R10 | Cancel descendants, including detached sessions | cgroup-wide kill and deletion; real detached-child test |
| R11 | Bound admitted jobs and retained output | admission/retention limits; capacity tests; 256 MiB configured retained-output ceiling |
| R12 | Persist state before acknowledging/executing work | atomic record replacement, fsync, audit writes; persistence-failure tests |
| R13 | Recover without repeating side effects | stale cgroup/workspace cleanup; queued/running records become interrupted; real SIGKILL/restart test |
| R14 | Stop admission after audit, persistence, or cleanup errors | quarantined service state and 503 readiness; injected failure tests |
| R15 | Avoid leaking code, args, credentials, or output to operational logs | metadata-only audit events and request IDs; private output records |
| R16 | Fail if required kernel/runtime controls are unavailable | startup validation and actual sandbox probe; unsupported-OS stub refuses execution |
| R17 | Expose explainable outcomes | terminal states, bounded output, exit status, wall/CPU/OOM/PID counters |
| R18 | Provide repeatable release evidence | pinned CI actions, race/vet/fuzz checks, native Linux integration harness, raw benchmark reports |

## Default budgets

Two workers; eight admitted jobs including running and queued work; 128 retained
records; ten-second default/thirty-second maximum job deadline; 256 MiB memory
and no swap per job; one CPU of bandwidth per job; 64 processes including the
launcher/init; 64 KiB stdout+stderr combined; 32 input files/256 KiB decoded file
content; 32 KiB total argument bytes; 1 MiB HTTP body and 8 KiB HTTP headers.

The unit additionally bounds the whole service to 1 GiB memory, 512 tasks, and
two CPUs of bandwidth. Changing worker/policy limits requires checking aggregate
host budgets. CPU bandwidth is a rate, not a cumulative CPU-time allowance.

Stored JSON may require up to six times the raw output budget because of JSON
escaping. Audit growth is capped at 128 MiB; reaching that cap quarantines work
until an operator archives the log. There is no silent audit truncation.

## Release gates

- Unit and HTTP tests, race detector, vet, formatting, and fuzz smoke tests pass.
- Real Linux integration tests run as an unprivileged account with actual
  cgroup delegation; skipped integration tests do not count as isolation proof.
- The deployed systemd unit passes the service verification and crash-recovery
  harness; rootfs and native seccomp artifacts match the selected release.
- Operator reviews the threat model, image/package inventory, operational
  runbook, retained-data policy, and remaining risks before expanding exposure.

An independent audit, operational soak under representative concurrency, and
external consumers are additional assurance work, not implied by test success.
