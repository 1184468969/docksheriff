# DockSheriff v0.1.0-rc.1 security review

Review dates: 2026-08-13 through 2026-08-14
Reviewed baseline: `d0091f0` (`main`)
Review scope: source, tests, workflows, release configuration, documentation,
and dependency design
Runtime scope: daemon-free automated tests plus a read-only rootful Linux Docker
25.0.5 Unix-socket smoke test; no container was created, started, stopped,
modified, or run privileged

## Executive summary

The baseline is small and intentionally read-only, and its existing unit, race, vet, and build checks pass. It is not ready for a public release candidate. The most important blockers are the hand-written Docker protocol client, ambiguous command parsing, incomplete rule semantics and coverage, output/error injection risks, an undocumented JSON contract, and incomplete release/security documentation.

This review treats every Docker Engine string and every transport error as untrusted. The remediation work must preserve the strict read-only boundary: only ping, server version, container list, and container inspect are needed. Docker Info is deliberately omitted because no current rule needs it.

## Findings

### Critical

#### SR-001: The Docker transport does not use the official SDK

`internal/engine/client.go` and `internal/dockerapi/types.go` implement API negotiation, transport, and Engine response types locally. This diverges from the intended SDK contract and makes TLS, endpoint parsing, API evolution, and response compatibility security-sensitive project code.

Required remediation: replace both with the official Docker Go SDK, construct the client with `client.FromEnv` and `client.WithAPIVersionNegotiation()`, expose only a minimal read-only interface, and put an independent timeout around every SDK call.

#### SR-002: Untrusted transport errors can disclose credentials or inject output

Several CLI paths print wrapped SDK/HTTP, URL, TLS-file, and argument errors directly. Endpoint redaction only protects one stored display string; it does not protect errors produced below that layer. Sanitization removes common ANSI and control sequences but has no uniform error boundary or length cap.

Required remediation: return stable public error categories, sanitize and truncate all variable text at the output boundary, redact endpoint userinfo and query data, and add hostile ANSI/OSC/C0/C1/bidi/invalid-UTF-8/long-value tests.

### High

#### SR-003: Command parsing is ambiguous and position-dependent

The baseline scans every argument for a command token. A flag value such as `--host inspect` can become a command, while Go's standard `flag` package stops parsing after the first positional argument. Help and version behavior is incomplete.

Required remediation: use an explicit two-phase parser (or a mature CLI framework) with deterministic global/subcommand flag behavior and comprehensive command-position tests.

#### SR-004: DS001-DS015 semantics and tests are incomplete

Only a few combined cases are tested. Linux host paths use `filepath`, raw bind strings are parsed by splitting on the first colon, DS008's capability set is incomplete, DS009 uses substring matching, DS010 ignores CDI and device requests, DS011 accepts only a subset of configured-root forms, and DS014 accepts malformed digest strings.

Required remediation: evaluate structured SDK inspect fields, use POSIX `path` semantics, document precise rule scope, and add positive, negative, boundary, and duplicate-suppression coverage for every rule.

#### SR-005: DS015 does not model the effective endpoint/TLS configuration robustly

The hand-written client derives insecure transport state from a simplified scheme/environment check. TLS material handling is stricter than Docker SDK behavior in some cases and error strings may reveal local paths.

Required remediation: base DS015 on the effective SDK endpoint and TLS verification configuration, never enable `InsecureSkipVerify`, cover host/environment precedence and TLS cases, and redact failures.

#### SR-006: JSON output is not a versioned deterministic contract

The baseline schema contains only `findings` and `count`; equal-severity ordering follows daemon scan order. Metadata, summary semantics, stable field names, sanitization guarantees, and compatibility expectations are undocumented.

Required remediation: publish schema version `1`, deterministic severity/container/rule sorting, a fixed summary object, stable finding fields, endpoint/server metadata that is safe to expose, and golden tests with an injected clock.

### Medium

#### SR-007: Human output omits the promised risk and remediation guidance

Table output prints a one-line summary but not the rule's `Risk`/`Remediation` content. It therefore does not provide the core Why/Fix workflow.

Required remediation: show a sanitized finding block with rule, severity, container, image, Why, and Fix; keep Low/Info collapsed by default but counted.

#### SR-008: Application concerns are coupled in one executable file

Command parsing, Docker construction, scanning, rule filtering, sorting, rendering, and exit codes live in `cmd/docksheriff/main.go`. This makes isolated fake-Engine and writer-failure tests difficult.

Required remediation: separate CLI parsing, application orchestration, Engine access, audit rules, output models/renderers, and executable wiring.

#### SR-009: Exit behavior is under-tested

The baseline does not cover all severity thresholds, ignored findings, invalid values, Engine failures, cancellation/timeouts, writer failures, or broken pipes.

Required remediation: fix exit codes at 0 (successful/no threshold), 1 (successful/threshold reached), and 2 (usage/connection/execution/output error), then test each boundary.

#### SR-010: CI and release configuration are incomplete

CI omits explicit non-race tests, format/tidy checks, lint, vulnerability scanning, timeouts, concurrency, and platform builds. CodeQL lacks job hardening. GoReleaser has not been snapshot-validated and does not inject version metadata or include release documentation/SBOM configuration.

Required remediation: harden workflows, validate all locally available tools, add version/commit/date injection, and run a clean snapshot release without publishing.

### Low

#### SR-011: Release, security, and contributor documentation is incomplete

The README is intentionally short; the project lacks rule semantics, JSON schema, threat model, security policy, contributing guide, code of conduct, changelog, notice, issue templates, PR template, Dependabot, and release notes.

Required remediation: add the missing files without claiming production readiness, comprehensive coverage, CIS compliance, or guaranteed security.

#### SR-012: Apache-2.0 attribution is embedded in the license text

The baseline `LICENSE` begins with whitespace and appends project copyright text to the canonical license.

Required remediation: keep the canonical Apache-2.0 text in `LICENSE` and move project attribution to `NOTICE`.

## Remediation status

The release-candidate worktree implements remediation for all twelve
source/repository findings above. Final closure is supported by the post-change
validation and independent re-audit recorded below:

- SR-001: replaced the hand-written protocol with the official split Moby
  API/client SDK modules, preserving `FromEnv`, `NewClientWithOpts`, and API
  negotiation. The injected Engine surface remains only ping, server version,
  container list, and container inspect, with an independent timeout per call.
- SR-002: public errors are fixed categories; endpoint credentials/query data
  are removed; ANSI CSI/OSC/DCS, C0/C1, CR/LF/tab, bidi, invalid UTF-8, and long
  values are covered by bounded sanitization tests.
- SR-003: the two-phase parser supports shared flags before, after, and within
  scan/inspect forms without treating flag values such as `--host inspect` as
  command tokens; help, version, and invalid inputs are covered.
- SR-004/SR-005: DS001-DS015 are covered across positive, negative, boundary,
  duplicate-suppression, and focused semantic matrices. Rule evaluation uses
  Linux path semantics, structured mounts, exact security options, the
  documented capability set, device mappings/cgroup rules/requests,
  configured-root semantics, the official reference parser, and effective
  endpoint/TLS metadata. Non-Linux or missing-platform Inspect data is rejected
  rather than evaluated under Linux assumptions.
- SR-006/SR-007/SR-009: JSON schema `1`, golden output, deterministic sorting,
  complete summaries, human Why/Fix blocks, thresholds, writer errors, and
  broken pipes are covered.
- SR-008: executable wiring, CLI, Engine adapter, application orchestration,
  rules, output, and safe-text handling are separated and fakeable.
- SR-010: CI/CodeQL are hardened; GoReleaser has version/commit/date injection,
  six target combinations, checksums, archive documentation, and SBOM config.
- SR-011/SR-012: release/security/contributor documentation and templates are
  present; `LICENSE` is canonical Apache-2.0 text and attribution is in NOTICE.

Independent follow-up review additionally identified SDK proxy inheritance,
unbounded response bodies, and broad SDK response types as defense-in-depth
gaps. Engine traffic now explicitly bypasses HTTP proxies, each response body
is limited to 32 MiB, and the adapter projects SDK results into types with no
environment, label, annotation, raw JSON, or command fields. List IDs remain
opaque Inspect targets and never enter findings or reports; projected Inspect
objects contain no ID field. Tests verify direct dialing, response-limit
failures, and the privacy-minimized type surface.

An independent follow-up rule-semantic review found and closed three additional
gaps: Moby's
legacy bare `disable` SELinux option, device cgroup rules, and ordered
`strconv.ParseBool` handling for repeated no-new-privileges options. Inspect
targets are now restricted before SDK path construction so an untrusted list ID
or CLI target cannot select a different Engine route. DS013 remains limited to
the explicit container security options visible in Inspect; it can report a
false positive when a daemon-wide no-new-privileges default applies, and this is
documented rather than widening the Engine interface to Docker Info.

Source validation passed locally, including Go 1.24.0 compatibility, Go
1.25.13 tests/vet/build, race tests, golangci-lint v2.12.2, and govulncheck
v1.6.0 (`No vulnerabilities found`). GoReleaser v2.12.0 and Syft v1.33.0
validated a clean snapshot from the exact committed candidate tree: six
archives, 12 verified checksum entries, six SPDX 2.3 SBOMs, 12 entries per
archive, and version metadata containing the source commit. A read-only live
smoke test also passed against rootful Docker Engine 25.0.5 over its Unix socket.
Hosted CI and CodeQL passed on PR #2 at commit `6612f5b` on 2026-08-14,
including the minimum/stable Go matrix and native Ubuntu, macOS, and Windows
jobs. The remaining rootless, Docker Desktop Linux-container-mode, verified-TLS,
empty/single-Engine, later Engine-version, and live cross-OS client matrix remain
publication blockers. No container was created, started, stopped, modified, or
run privileged during this review.

## Remediation verification

The release-candidate source and exact committed snapshot passed the following
local checks, with the final toolchain refresh completed on 2026-08-14:

```text
GOTOOLCHAIN=go1.24.0 go test ./...
GOTOOLCHAIN=go1.25.13 go test ./...
GOTOOLCHAIN=go1.25.13 go test -race ./...
GOTOOLCHAIN=go1.25.13 go vet ./...
GOTOOLCHAIN=go1.25.13 go build ./cmd/docksheriff
GOTOOLCHAIN=go1.25.13 golangci-lint run
GOTOOLCHAIN=go1.25.13 govulncheck ./...
goreleaser check
GOTOOLCHAIN=go1.25.13 goreleaser release --snapshot --clean
git diff --check
```

An initial vulnerability-database request returned a transient EOF through the
configured HTTP proxy. A direct-network retry succeeded. On 2026-08-14, a fresh
database scan then identified GO-2026-6218, GO-2026-6090, GO-2026-5972, and
GO-2026-5026 in the Go 1.25.12 standard library, all fixed by Go 1.25.13. The
1.25.12 artifacts were discarded; the final gate and release snapshot use Go
1.25.13 and report `No vulnerabilities found`.

The clean snapshot contains Linux, macOS, and Windows archives for amd64 and
arm64. All 12 checksum entries passed, all six archive SBOMs identify SPDX 2.3,
and every archive contains the binary plus 11 expected license, policy, and
project documents. The Linux amd64 binary reports the snapshot version, full
source commit, and build date injected by ldflags.

## Live read-only smoke verification

On 2026-08-14, the committed Linux amd64 candidate was exercised against an
existing rootful Docker Engine 25.0.5 (API 1.44) on Linux amd64 through
`unix:///var/run/docker.sock`. The daemon already contained 11 running and 8
stopped containers; the test did not change that state.

The following paths passed. The repository record contains only aggregate
results; it does not include complete reports, Inspect payloads, container IDs,
environment values, or arbitrary labels:

- default JSON scan of all 11 running containers;
- `--all` JSON scan of all 19 containers, including the 8 stopped containers;
- single-container JSON inspection of one existing running container and one
  existing stopped container;
- explicit `--host unix:///var/run/docker.sock` and equivalent `DOCKER_HOST`
  selection;
- repeated scan comparison after removing only `generated_at`, with identical
  normalized output;
- table output containing Why, Fix, and Summary with no ANSI escape byte;
- `--fail-on critical`, which completed the scan and returned status 1.

Every JSON report used schema version 1 and the documented top-level fields. A
recursive key check found no Env, Labels, Annotations, command, entrypoint, or
full-ID field. This closes one rootful/Unix-socket/Docker-25/multiple-and-stopped
matrix row. Rootless Docker, Docker Desktop Linux-container mode, verified TLS,
empty and single-container Engines, Docker 26.x/27.x/current, and macOS/Windows
clients remain unverified publication blockers.

## Baseline verification

The following commands passed at `d0091f0` before remediation:

```text
git diff --check
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/docksheriff
```

Passing baseline tests do not close the findings above because the vulnerable and ambiguous cases are not represented in the existing suite.
