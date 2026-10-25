# Changelog

## 0.1.0 — 2026-10-25

Initial implementation: local authenticated job API, Go client/service, mandatory
Linux namespace/cgroup/seccomp backend, immutable runtime builder, durable state
and audit, cancellation/restart handling, real isolation/evaluation tools,
systemd deployment, CI, requirements, threat model, and recorded local evidence.

Scope remains a dedicated single-host execution service. Remote multi-tenant
hosting, network egress, GPU access, microVMs, and production operating history
are not included in this release.
