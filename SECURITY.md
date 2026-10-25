# Security policy

This implementation uses Linux namespaces, cgroup v2, bubblewrap, and a native
seccomp allowlist. These mechanisms share the host kernel. A VM boundary is
required when the threat model includes hostile kernel exploitation.

Read [the threat model](docs/THREAT_MODEL.md) and
[deployment requirements](docs/DEPLOYMENT.md) before executing untrusted inputs.
There is no permissive or unsandboxed execution mode.

Report suspected vulnerabilities privately to dpatel57963@gmail.com. Include
the affected release, kernel/bubblewrap versions, minimal reproduction, expected
boundary, and observed result. Do not include real credentials, private customer
data, or attacks against infrastructure you do not control.

No response-time SLA or independent security certification is claimed. Confirm
maintenance and disclosure arrangements before relying on a release commercially.
