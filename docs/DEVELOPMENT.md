# Windows and Mac development

## Host-independent checks

The client, policy, authentication, API, scheduler, persistence, and audit tests
run on Windows/macOS/Linux. The Linux backend has an explicit unsupported-OS
implementation that refuses execution. There is no fake execution switch in the
production server.

```sh
go test ./...
go vet ./...
go test ./internal/policy -run '^$' -fuzz FuzzValidFileName -fuzztime 10s
go test ./internal/strictjson -run '^$' -fuzz FuzzDecode -fuzztime 10s
```

Race tests need a supported C compiler/toolchain. `go test -race ./...` is part
of the Linux CI job. All Go production dependencies are standard library.

## Linux VM

On macOS, run the execution host in a Linux VM and build the native rootfs/filter
there. Do not use the host macOS filesystem or a privileged Docker container as
an interchangeable substitute for the documented VM boundary. Apple Silicon
needs a matching arm64 guest and a filter generated inside that guest.

On Windows, a WSL2 Ubuntu distribution can run the Linux tests if it has the
required namespace, seccomp, and cgroup v2 features. WSL is a development target,
not a demonstrated production deployment.

For the isolated `AgentExecTest` distribution created during local verification:

- Portable Windows Go is under `C:\Users\Deep\.cache\agent-exec-tools\go`.
- The Linux toolchain is `/opt/go/bin/go` inside that distribution.
- `/etc/wsl.conf` enables systemd. The newly created host `.wslconfig` enables
  unified cgroups using `systemd.unified_cgroup_hierarchy=1 cgroup_no_v1=all`.
- This was configured only after verifying that there were no existing WSL
  distributions or host `.wslconfig`. That host setting applies to WSL generally;
  review it before adding other WSL workloads.
- `tools/dev/prepare-wsl.sh` is guarded to that named test distribution. It does
  not weaken the production backend and never disables host security controls.
- WSL may stop even with systemd services running. Keep a WSL terminal/session
  open while exercising transient test services. Transient `systemd-run` units
  disappear after that WSL instance stops.

The local verification fixture uses versioned image/filter paths
`/opt/agent-exec/rootfs-v2` and `/opt/agent-exec/default-v2.bpf`; the installer uses
the unversioned paths in the sample config for a fresh deployment.

## Real isolation suite

Do not count skipped tests as isolation proof. The explicit `integration` build
tag requires all fixture paths and fails if they are missing.

On an Ubuntu execution host after building the image/filter:

```sh
sudo useradd -m -s /bin/bash agentexec-test
sudo install -d -m 0700 -o agentexec-test -g agentexec-test /var/lib/agent-exec-test
sudo systemd-run --unit=agentexec-integration --wait --pipe --collect \
  --uid=agentexec-test --property=Delegate=yes --working-directory="$PWD" \
  /usr/bin/env PATH="$PATH" bash tools/run-integration.sh
```

The test account must be able to read/traverse the repository and execute Go;
put the checkout somewhere appropriate rather than opening a private home
directory indiscriminately. CI adjusts only its ephemeral checkout ancestors.

`tools/run-integration.sh` moves its trusted shell to a supervisor leaf before
running Go, ensuring compiler/test wrapper processes don't keep the delegated
parent populated. The backend does this itself for the production server.

Optional syscall diagnostics require strace and `AGENTEXEC_TRACE=1`; they go to
the private test-state directory. Use traces only with synthetic fixtures.

## Changes to the syscall policy

Add a syscall only after tracing a failing legitimate workload, identifying its
purpose, adding an appropriate argument restriction where possible, and adding
a regression. For example, Python opening a script requires the `FIOCLEX`
descriptor ioctl. The filter permits that exact operation rather than all ioctl
requests. Keep architecture-specific tests; an amd64 BPF artifact is not portable
to arm64.

## Source references

- [bubblewrap](https://github.com/containers/bubblewrap) and its
  [CLI specification](https://github.com/containers/bubblewrap/blob/main/bwrap.xml)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [clone3 and CLONE_INTO_CGROUP](https://man7.org/linux/man-pages/man2/clone.2.html)
- [seccomp](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [Go release policy](https://go.dev/doc/devel/release)
