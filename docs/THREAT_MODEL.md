# Threat model

## Assets and trust

Protect the host filesystem, service credentials and environment, other jobs'
inputs/output, control-plane integrity, audit continuity, and bounded host
resources. The adversary controls job argv, input filenames/content, stdout,
stderr, fork/exec behavior, and code run inside the approved runtime.

Trusted: the Linux kernel, hypervisor/VM boundary when used, systemd, bubblewrap,
the Go service/runtime, C policy generator/libseccomp, operator-built rootfs,
and deployment administrator. The administrator chooses and updates artifacts.
An LLM, a prompt, a submitted script, and generated tool arguments are untrusted.

## Abuse cases

| Attempt | Control | Residual risk |
|---|---|---|
| Read SSH/cloud/API credentials | only minimal image and job inputs mounted; clear environment | host/kernel escape defeats this boundary |
| Traverse supplied filenames into host paths | clean relative ASCII paths; no symlinks/archive uploads; fresh private input directory | operator-controlled runtime paths remain trusted |
| Change interpreter or policy files | immutable host-owned image and read-only bind | privileged operator can replace the image |
| Exfiltrate via network or local host services | separate net namespace; socket syscalls denied; no inherited network FDs | output is an intentional channel to the authenticated caller |
| Fork before resource placement | atomic clone into limited cgroup | kernel correctness is trusted |
| Escape cleanup with setsid/double fork | cgroup-wide kill and subtree removal; systemd KillMode=control-group | a kernel task stuck uninterruptibly may require operator action |
| Consume CPU, memory, processes, or output indefinitely | cgroup bounds, no swap, deadline, combined output cap | authenticated callers can consume the bounded shared capacity |
| Use alternate kernel attack interfaces | default-deny seccomp; no caps/nested namespaces; minimal device view | allowed syscalls can still contain kernel vulnerabilities |
| Read/cancel another caller's job | principal derived from authenticated credential; uniform 404 | stolen bearer credentials impersonate their owner |
| Forge request identity or ambiguous JSON | no principal/env/host-mount request fields; strict duplicate/unknown field rejection | operator token configuration must be correct |
| Hide execution by exhausting audit storage | fsynced events, bounded log, quarantine on error | output for interrupted jobs can be lost; availability is sacrificed |
| Repeat work after daemon crash | cleanup and interrupted state; no automatic replay | callers must decide whether retrying their own work is safe |

## Explicit limitations

- Shared-kernel containment does not protect against kernel zero-days or all
  microarchitectural side channels. Use a dedicated VM and strengthen the
  boundary before accepting unknown Internet tenants.
- This release deliberately denies all guest networking, even loopback/Unix
  sockets. An egress proxy, DNS policy, and credential broker are future work.
- The runtime image is built from trusted, distro-installed binaries. Its
  manifest is an inventory, not a signature or automatic attestation mechanism.
- Jobs can copy their own inputs to their own stdout. This system does not
  prevent an authorized caller from disclosing data it already possesses.
- There are no per-principal fair-share quotas or separate hardware per user.
  API ownership checks should not be described as strong SaaS tenant isolation.
- Stored output may contain secrets. Keep state and backups private and set an
  operational retention policy; no automated content redaction is claimed.
- Hash chaining alone does not resist a privileged full-log rewrite. Export to
  an independently protected sink before making audit-integrity claims.
- This implementation has tests and local verification, not a third-party audit,
  certification, proof of escape resistance, or established production SLO.
