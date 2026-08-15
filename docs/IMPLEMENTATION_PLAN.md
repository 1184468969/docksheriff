# v0.1.0-rc.1 implementation plan

This plan was written from the independent review of baseline commit `d0091f0`, before implementation changes.

## Safety invariants

- Keep the Docker surface limited to ping, server version, container list, and container inspect. Do not add Info unless a documented rule later requires it.
- Never add Docker mutation, exec/cp, environment reads, arbitrary-label reads/output, telemetry, or non-Engine network access.
- Give every Engine call a fresh timeout context.
- Treat all Engine strings and underlying errors as hostile; expose only sanitized, length-limited public text.
- Keep tests daemon-free and unprivileged.
- Do not push, tag, or publish.

## Work sequence

1. Replace the local protocol implementation with the official Docker SDK and a minimal injected `Engine` interface. Add transport/TLS/timeout/redaction tests and compile-time interface-surface checks.
2. Move rule evaluation onto structured SDK inspect types. Correct path, security-option, capability, device, configured-user, image-reference, and endpoint/TLS semantics. Build a table-driven matrix for DS001-DS015, including duplicates.
3. Split executable wiring, CLI parsing, application orchestration, output rendering, and exit-code policy. Support global flags before or after `scan`/`inspect`, complete help/version behavior, and fake-Engine tests.
4. Publish JSON schema `1` with an injectable clock, safe Docker metadata, severity summary, stable finding fields, and deterministic severity/container/rule ordering. Add JSON golden and writer-failure tests.
5. Render human findings with Rule/Severity/Container/Image/Why/Fix. Sanitize before rendering and keep Low/Info collapsed by default.
6. Add release/security/project documentation, issue/PR templates, Dependabot, hardened CI/CodeQL, GoReleaser metadata injection, archives, checksums, and SBOM settings.
7. Run `gofmt`, `go mod tidy`, unit tests, race tests, vet, build, format/tidy diff checks, lint, vulnerability scan, GoReleaser check/snapshot, and `git diff --check`. Record unavailable tools or environmental blockers exactly.
8. Re-read the complete diff for read-only API drift, sensitive fields, unsafe errors, network additions, workflow privileges, and documentation overclaims. Commit the verified result on `codex/v0.1.0-rc1-readiness` without pushing.

## Acceptance evidence

The final handoff will include the closed/open status of every security-review finding, file references, exact validation commands and results, any tool/environment limitations, and confirmation that no tag, push, release, Docker mutation, or privileged test occurred.
