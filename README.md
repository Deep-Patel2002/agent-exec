# Agent Exec

A local execution service for agent-generated Python and shell workloads, with
Linux-enforced containment and an authenticated, asynchronous HTTP API.

The control plane and client are Go, the seccomp policy generator is C, and the
evaluation harness is Python. The Go module has no third-party dependencies.

## What ships

- Fixed, read-only runtime image and inputs; private ephemeral `/work` and `/tmp`.
- Required user, mount, PID, network, IPC, UTS, and cgroup namespaces.
- Default-deny seccomp, no capabilities, no inherited host environment, and no
  network syscalls in the initial policy.
- Atomic `CLONE_INTO_CGROUP` placement before launching bubblewrap, memory/swap,
  CPU-bandwidth, and process limits; `cgroup.kill` descendant cleanup.
- Bounded queue and combined stdout/stderr budget; deadlines and cancellation.
- Hashed bearer credentials, per-principal job access, strict JSON, private
  records, synchronous audit writes, crash recovery without replay, and metrics.
- Linux isolation tests, cross-platform control-plane tests, fuzz targets,
  systemd deployment, API specification, and reproducible verification tools.

**Release scope:** one dedicated Linux host/VM and a loopback API. The system
shares a Linux kernel; it is not a microVM service or a public multi-tenant SaaS.
No independent security audit or production operating history is claimed.

## Start here

1. [Requirements and acceptance criteria](docs/REQUIREMENTS.md)
2. [Scope and architecture](docs/ARCHITECTURE.md)
3. [Threat model](docs/THREAT_MODEL.md)
4. [Deployment and operations](docs/DEPLOYMENT.md)
5. [Windows/Mac development](docs/DEVELOPMENT.md)
6. [Verified results and benchmark limits](docs/VERIFICATION.md)
7. [API contract](api/openapi.yaml)

## Build and verify

Use a supported Go release (tested with **Go 1.27.3**). The code requires Go 1.25+.

```sh
go test ./...
go vet ./...
# Linux/macOS with a C compiler:
go test -race ./...
```

Execution requires Linux, unified cgroup v2, a delegated systemd unit, non-setuid
bubblewrap 0.9+, and a dedicated unprivileged account. Windows and macOS can
build the client and run control-plane tests; they cannot run the Linux backend.

On a dedicated Ubuntu 24.04+ VM with the required kernel support:

```sh
sudo apt-get update
sudo apt-get install -y bubblewrap libseccomp-dev gcc make python3
make build seccomp
sudo bash tools/install-local.sh
sudo systemctl start agent-exec.service
sudo systemctl status agent-exec.service
```

The installer creates a local credential without printing it. For an installed
service, submit as its service account (or transfer the client credential through
an appropriate private channel):

```sh
sudo -u agentexec /opt/agent-exec/bin/agent-exec \
  -token-file /var/lib/agent-exec/auth/client.token \
  submit examples/hello.json

sudo -u agentexec /opt/agent-exec/bin/agent-exec \
  -token-file /var/lib/agent-exec/auth/client.token wait JOB_ID
```

`get JOB_ID`, `cancel JOB_ID`, and `list` use the same global flags. Input files
are supplied as UTF-8 strings in the JSON request; host paths and environment
variables are never accepted. Results return bounded output, exit status, and
resource counters. Listings return metadata only.

The default executable set is `/usr/bin/python3` and `/bin/sh`. This limits entry
points, not the general capabilities of arbitrary code inside the sandbox. The
OS policy remains the enforcement boundary.

## Repository

```text
cmd/agent-exec/          cross-platform authenticated client and credential setup
cmd/agent-exec-server/   Linux service entry point and readiness probe
internal/api/           authentication, ownership checks, HTTP limits
internal/service/       admission, scheduling, state transitions, recovery
internal/sandbox/       bubblewrap/cgroup backend and real Linux tests
internal/policy/        immutable operator limits and request validation
internal/store/         atomic private job records
internal/audit/         flushed, bounded, hash-chained audit log
tools/seccompgen.c      native-architecture syscall allowlist
tools/                  rootfs builder, deployment, verification, benchmark tools
deploy/                 hardened systemd unit
api/                    OpenAPI contract
docs/                   design, threat model, requirements, operations, evidence
```

Benchmark numbers are observations, not SLOs. See the committed verification
report before reusing them in a resume or LinkedIn post.
