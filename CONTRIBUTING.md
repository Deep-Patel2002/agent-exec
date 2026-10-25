# Contributing

Run `make test race vet fmt-check` on Linux. Execute the explicit integration
suite in a delegated cgroup for changes to mounts, syscalls, runtime images,
limits, launch, or cleanup. Use synthetic inputs in debugging traces and reports.

Changes to authentication, ownership, parsing, or persistence need corresponding
fault/negative tests. Changes to enforcement should update the requirement and
threat-model documents. Keep stdout/stderr, code, credentials, and argv out of
operational logs. There is no approval to contact third parties or publish data
implied by running local verification.

Do not add an unsandboxed fallback, silently skip required controllers, migrate
untrusted children into cgroups after spawn, or claim an unmeasured benchmark.
Use established cryptographic/runtime primitives and explicitly document any
expanded trust boundary.
