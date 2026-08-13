# DockSheriff v0.1.0-rc.1 release notes

Status: draft release-candidate notes. No tag or GitHub Release has been created
from this document.

`v0.1.0-rc.1` is intended to be the first limited-feedback release of
DockSheriff, a read-only checker for security-sensitive configuration of Linux
containers. It should be evaluated by a small group before `v0.1.0`; it is not
described as production-ready or as a complete security audit.

## Highlights

- `scan` audits running containers; `--all` includes stopped containers.
- `inspect CONTAINER` audits one named container or ID.
- `rules` lists DS001-DS015 and `explain RULE` shows risk and remediation.
- Table output expands findings with Container, Image, Why, and Fix fields.
- JSON schema version 1 provides sanitized Docker metadata, a full severity
  summary, stable finding fields, and deterministic ordering.
- `--min-severity`, repeatable `--ignore`, and `--fail-on` support human and CI
  policy workflows with documented exit status 0, 1, and 2.
- The official Docker Go SDK supplies endpoint environment handling and API
  version negotiation behind a minimal read-only Engine interface.
- Every Engine call has a separate timeout; tests use fakes and fixtures and do
  not require a Docker daemon or privileged container.
- Engine traffic bypasses HTTP proxy environment variables, response bodies are
  limited to 32 MiB, and broad SDK objects are projected into types that expose
  no environment, label, annotation, raw JSON, or command fields. List IDs are
  opaque Inspect targets and are never included in findings or reports.

## Security and privacy design

DockSheriff invokes only ping, server version, container list, and container
inspect. It does not mutate Docker objects, exec/copy, pull images, evaluate or
print container environment values or arbitrary labels, print complete Inspect
responses, contact non-Engine network services, upload results, or send
telemetry. The official SDK decodes the Engine's broad response before the
adapter immediately projects only rule-required fields; sensitive unrelated
fields cannot cross the Engine interface.

Engine and argument strings are treated as untrusted. Public output removes
terminal controls and bidirectional control characters, bounds text length, and
redacts Docker endpoint username, password, query, and fragment data. TLS
certificate verification is never deliberately disabled.

These controls do not remove the privilege inherent in Docker access. A
rootful Docker socket commonly grants host-level authority to the process that
can open it. Review [the threat model](THREAT_MODEL.md) before deployment.

## Rule set

The release candidate defines:

- Critical: privileged mode, Docker socket bind, host-root bind, container
  runtime data bind, and effectively unencrypted Docker TCP endpoint;
- High: sensitive host binds, host network/namespace sharing, an explicit set
  of dangerous capabilities, disabled mandatory profiles, and device access;
- Medium: configured root user, writable root filesystem, and missing
  explicit no-new-privileges;
- Low: implicit, latest, or invalid image reference.

See [the rule reference](RULES.md) for exact structured fields, path boundaries,
capability list, security-option forms, user semantics, image parser behavior,
TLS interpretation, and false-positive/false-negative limitations.

## JSON compatibility

Consumers should require `schema_version == "1"` and follow
[the schema contract](JSON_SCHEMA.md). `generated_at` changes on each run;
finding order does not depend on Docker's container-list order. JSON never
contains ANSI styling, environment values, arbitrary labels, complete Inspect
responses, endpoint credentials, or full container IDs.

## Artifacts planned for the release

GoReleaser is configured to build `docksheriff` for:

- Linux amd64 and arm64 (`tar.gz`);
- macOS amd64 and arm64 (`tar.gz`);
- Windows amd64 and arm64 (`zip`).

Each archive includes the license, notice, README, changelog,
contributor/security/conduct policies, and core rule, schema, threat-model, and
release-note documents. The release also plans SHA-256 checksums and an SBOM for
every archive. Artifact signing and verifiable provenance are not part of this
candidate and must not be inferred from checksums or SBOMs.

## Known limitations

- This is pre-release software and has not been proven against every Docker
  version, platform, transport, or workload.
- v0.1 rules audit Linux containers only. Binaries can run on Linux, macOS, or
  Windows, but non-Linux or missing-platform Inspect data is rejected.
- DockSheriff does not scan image CVEs, packages, secrets, malware, provenance,
  application traffic, or broad host/daemon configuration.
- Inspect metadata cannot identify a bind-source symlink to the Docker socket or
  another sensitive path.
- DS011 checks the configured user string, not the actual UID of a running
  process; a non-numeric username is unresolved.
- DS013 checks explicit container security options and cannot observe a
  daemon-wide no-new-privileges default, which can cause a false positive.
- Rules are heuristics and can produce false positives and false negatives.
- A compromised Engine can return false or inconsistent data.
- A successful scan does not prove security or CIS compliance.

## Verification gate before publishing

Local source validation on 2026-08-13 passed with Go 1.24.0 and Go 1.25.12.
`govulncheck v1.6.0` reports `No vulnerabilities found` with Go 1.25.12 after
replacing the broad legacy Docker module with the official split Moby API/client
modules. A clean GoReleaser snapshot from the exact committed candidate tree
also passed. The repository remains unpublished: the candidate still needs
hosted CI/CodeQL evidence and the representative read-only Docker smoke-test
matrix below.

These notes must not be used to publish the candidate until the exact release
commit passes:

```sh
gofmt -w $(find . -name '*.go' -type f)
go mod tidy
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/docksheriff
golangci-lint run
govulncheck ./...
goreleaser check
goreleaser release --snapshot --clean
git diff --check
```

The exact-commit snapshot used GoReleaser v2.12.0, Syft v1.33.0, and Go 1.25.12.
It produced all six planned OS/architecture archives, 12 verified SHA-256
entries covering archives and SBOMs, and six SPDX 2.3 archive SBOMs. Every
archive contains the expected binary plus 11 license, policy, and project
documents. The Linux amd64 binary's `--version` output contains the snapshot
version, full source commit, and build date injected by ldflags.

Read-only smoke testing is also required on representative rootful and rootless
Docker, Docker Desktop in Linux-container mode, Unix-socket and verified-TLS
TCP connections, an empty Engine, single/multiple containers, and `--all` with a
stopped container. Docker Engine 25.x, 26.x, 27.x, and a current supported
version are intended targets when test environments are available. Automated
tests remain daemon-free and never require privileged containers.

No live Docker smoke test was performed during this review. Hosted CI/CodeQL
and the Docker smoke-test matrix have not yet been completed and remain
publication blockers. At publication time, replace this section with the exact
commands, versions, platforms, and outcomes. If a tool or environment is
unavailable, disclose the gap rather than implying it passed.

## Feedback and reporting

Use the repository's structured forms for redacted bugs, false positives, and
rule proposals. Never paste endpoint credentials, passwords, tokens, private
keys, environment variables, arbitrary labels, internal identifiers, or full
Inspect JSON. Report vulnerabilities privately as described in
[SECURITY.md](../SECURITY.md).
