# DockSheriff

DockSheriff is a small, read-only checker for security-sensitive configuration
of Linux containers known to a Docker Engine.

It evaluates 15 documented rules and presents the risk and a manual remediation
for each finding. It is intentionally narrower than an image vulnerability
scanner or a complete host audit.

> **Status:** DockSheriff is pre-release software being prepared for
> `v0.1.0-rc.1`. Interfaces and rule boundaries may still change to address a
> security or correctness issue. Do not treat a clean result as proof that a
> container, image, daemon, or host is secure.

No release should be inferred from this repository state. Publication remains
gated on the exact-commit CI run and the read-only Engine smoke-test matrix in
the [release notes](docs/RELEASE_NOTES_v0.1.0-rc.1.md).

## Safety and privacy boundary

DockSheriff uses only these Docker Engine operations:

- ping;
- server version;
- container list;
- container inspect.

Each operation has its own timeout and each Engine response is limited to 32
MiB. TCP/HTTP(S) Engine traffic connects directly to the selected endpoint and
does not inherit HTTP proxy environment variables. DockSheriff does not create,
start, stop, restart, update, remove, exec into, or copy from a container. It
does not mutate networks or volumes, pull images, evaluate or output container
environment values or arbitrary labels, print complete Inspect responses,
contact registries or update services, upload reports, or send telemetry.

All Docker strings are treated as untrusted and public output is sanitized and
length-limited. Docker endpoint usernames, passwords, query parameters, and
fragments are removed from displayed metadata. These safeguards reduce common
credential and terminal-injection risks; output can still reveal container
names, image references, hostnames, or socket paths. Review and redact a report
before sharing it.

### Docker access is privileged

Access to a rootful Docker socket is commonly equivalent to host-level control.
DockSheriff calls it read-only, but the user or container running DockSheriff
still holds whatever authority the endpoint grants. Protect the process and
socket, use the narrowest practical operating-system permissions, and do not
expose an unauthenticated TCP daemon for scanning. See the
[threat model](docs/THREAT_MODEL.md).

## Installation

DockSheriff's module currently requires Go 1.24 or newer to build from source.

Until a release candidate has been published, install the current source only
after reviewing the commit you intend to run:

```sh
git clone https://github.com/1184468969/docksheriff.git
cd docksheriff
go build -trimpath -o ./docksheriff ./cmd/docksheriff
./docksheriff --version
```

After a release exists, prefer an archive from the repository's Releases page,
verify it against the published `checksums.txt`, and inspect the accompanying
SBOM. The project does not yet claim signed artifacts or verifiable provenance.

`go install github.com/1184468969/docksheriff/cmd/docksheriff@<tag>` is another
source-based option once a tag exists. Pin an exact tag; do not substitute
`@latest` when reproducibility matters.

## Quick start

The default command scans running containers on `DOCKER_HOST`, or the standard
local Docker socket when that variable is unset:

```sh
docksheriff
docksheriff scan
docksheriff inspect portainer
```

Scan stopped containers as well, emit JSON, or enforce a CI threshold:

```sh
docksheriff scan --all
docksheriff --format json scan
docksheriff scan --fail-on high
```

Example human output (values are illustrative and sanitized):

```text
DockSheriff
Docker:  unix:///var/run/docker.sock (server 28.5.2, API 1.51)
Scanned: 1 container(s)

CRITICAL DS002  Docker socket mounted
Container: example
Image:     example/app:1.2.3
Why:      The Docker socket normally grants host-level control.
Fix:      Remove the socket mount or use a narrowly scoped proxy.

Summary: critical=1 high=0 medium=1 low=0 info=0 total=2
```

By default, table output expands Medium and higher findings. Low and Info still
appear in the summary. JSON always includes every non-ignored finding.

## Command-line interface

```text
docksheriff [global flags] [scan] [scan flags]
docksheriff [global flags] inspect CONTAINER [inspect flags]
docksheriff rules
docksheriff explain RULE
docksheriff --help
docksheriff --version
```

Shared scan/inspect flags can appear before or after `scan` or `inspect`:

| Flag | Meaning |
| --- | --- |
| `--format table\|json` | Select human or schema-versioned output. Default: `table`. |
| `--min-severity SEVERITY` | Minimum severity expanded in table output. Default: `medium`. |
| `--fail-on SEVERITY` | Exit 1 when at least one non-ignored finding meets this threshold. |
| `--ignore RULE` | Exclude one rule; repeat for multiple IDs. |
| `--all` | Include stopped containers in a scan. |
| `--host ENDPOINT` | Override `DOCKER_HOST` for this invocation. |

Severity values are `critical`, `high`, `medium`, `low`, and `info`, matched
case-insensitively. `--ignore` should be used only after the exception has been
reviewed and documented outside DockSheriff.

Useful metadata commands:

```sh
docksheriff rules
docksheriff explain DS002
docksheriff --help
```

### Endpoint and TLS behavior

Without `--host`, Docker SDK environment settings such as `DOCKER_HOST`,
`DOCKER_TLS_VERIFY`, `DOCKER_CERT_PATH`, and `DOCKER_API_VERSION` select the
Engine connection. An explicit `--host` overrides `DOCKER_HOST`; the TLS
settings still apply. Unix sockets and verified TLS TCP endpoints do not produce
DS015. An effectively unencrypted TCP endpoint does, regardless of whether its
port is conventionally associated with TLS. DockSheriff does not enable
`InsecureSkipVerify`. `HTTP_PROXY`, `HTTPS_PROXY`, and related proxy settings
are deliberately ignored for Engine traffic so they cannot widen the configured
network boundary.

## Rules

| ID | Severity | Check |
| --- | --- | --- |
| DS001 | Critical | Privileged container |
| DS002 | Critical | Docker socket mounted |
| DS003 | Critical | Host root mounted |
| DS004 | Critical | Container runtime data mounted |
| DS005 | High | Sensitive host path mounted |
| DS006 | High | Host network namespace |
| DS007 | High | Host namespace shared |
| DS008 | High | Dangerous capability added |
| DS009 | High | Mandatory security control disabled |
| DS010 | High | Host device exposed |
| DS011 | Medium | Container configured to run as root |
| DS012 | Medium | Writable root filesystem |
| DS013 | Medium | No explicit no-new-privileges |
| DS014 | Low | Image uses an implicit or latest tag |
| DS015 | Critical | Unencrypted Docker TCP endpoint |

The exact paths, capabilities, security options, user-string behavior, image
reference parsing, endpoint semantics, limitations, and remediation text are in
the [rule reference](docs/RULES.md). Rules can have false positives and false
negatives; their absence does not certify compliance.

## JSON output

Schema version 1 includes a generation time, redacted Docker metadata, scanned
container count, complete severity summary, and stable finding fields:

```json
{
  "schema_version": "1",
  "generated_at": "2026-08-13T07:00:00Z",
  "docker": {
    "endpoint": "unix:///var/run/docker.sock",
    "server_version": "28.5.2",
    "api_version": "1.51"
  },
  "scanned_containers": 0,
  "summary": {
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0,
    "info": 0,
    "total": 0
  },
  "findings": []
}
```

Findings sort by severity descending, container name ascending, then rule ID.
JSON contains no ANSI styling, environment values, arbitrary labels, endpoint
credentials, complete Inspect response, or full container ID. See the complete
[JSON schema contract](docs/JSON_SCHEMA.md) before building an integration.

## Exit status

| Status | Meaning |
| --- | --- |
| `0` | The command succeeded and no enabled `--fail-on` threshold was reached. |
| `1` | The scan succeeded and at least one non-ignored finding met `--fail-on`. |
| `2` | Arguments, Docker connection/execution, incomplete Engine data, or output failed. |

Without `--fail-on`, findings do not by themselves produce status 1. Status 2
means a complete successful report was not produced; do not treat it as a clean
scan. A downstream broken pipe is an output failure.

## Platform support and testing status

CI is configured to build and run daemon-free unit tests on Linux, macOS, and
Windows with the module's minimum and current stable Go releases where
applicable. GoReleaser is configured for Linux, macOS, and Windows on amd64 and
arm64.

Those binaries audit Linux containers only. A Windows or macOS binary can
connect to a remote Linux Engine or Docker Desktop in Linux-container mode;
Inspect data with a missing or non-Linux platform is rejected with status 2 to
avoid applying Linux rules to Windows containers. The build matrix verifies
compilation and fixture behavior, not compatibility with every Docker Engine
or host configuration. Before `v0.1.0`, maintainers intend to perform read-only
smoke tests against rootful and rootless Docker, Docker Desktop in
Linux-container mode, Unix sockets, and verified TLS endpoints. See the
[release-candidate notes](docs/RELEASE_NOTES_v0.1.0-rc.1.md) for the exact
verification status.

## Known limitations

- DockSheriff examines a non-atomic configuration snapshot from one Docker
  Engine; state can change during a scan.
- A malicious or compromised Engine can lie, omit data, or return inconsistent
  responses.
- Inspect metadata cannot show that a different bind source is a symlink to a
  sensitive path such as the Docker socket.
- Configured usernames are not resolved to a runtime UID. A non-numeric name is
  not proof of non-root execution.
- DS013 checks container-level `SecurityOpt` data. Docker's daemon-wide
  no-new-privileges default is not represented there, so an Engine using that
  default can produce a DS013 false positive when the container has no explicit
  override.
- Rules cover a deliberately small set of container configuration fields; they
  do not audit every daemon, host, kernel, network, storage, or identity control.
- No image CVE, package, malware, secret, SBOM provenance, or application
  traffic scanning is performed.
- Release artifact signing and verifiable provenance are not part of the
  current release configuration.

## Relationship to other tools

DockSheriff complements rather than replaces Trivy, Dockle, and Docker Bench for
Security. Image/package scanners identify vulnerable dependencies; image
linters evaluate build-time practices; host benchmarks inspect broader daemon
and host configuration. DockSheriff focuses on 15 configuration checks for
containers already known to one Engine. Use several layers of tooling and
review the evidence in workload context.

## Development and contributing

Tests use fake Engines and fixtures. They require neither a Docker daemon nor
privileged containers.

```sh
gofmt -w $(find . -name '*.go' -type f)
go mod tidy
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/docksheriff
golangci-lint run
govulncheck ./...
git diff --check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before proposing a rule or behavior
change. The repository's safety boundary is part of the contribution contract.

## Security

Do not post credentials, environment variables, arbitrary labels, private
keys, or complete Docker Inspect output in a public issue. Use the private
process described in [SECURITY.md](SECURITY.md) for vulnerabilities.

## License

DockSheriff is licensed under the [Apache License 2.0](LICENSE). Project
attribution is in [NOTICE](NOTICE).
