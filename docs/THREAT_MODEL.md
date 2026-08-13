# Threat model

This document defines what DockSheriff is designed to protect, which inputs it
treats as hostile, and what a scan does not establish. It describes the
intended v0.1 boundary rather than certifying a particular Docker deployment.

## Purpose and assets

DockSheriff inspects selected configuration of existing Docker containers and
reports risky settings. The security goals are to:

- avoid changing Engine or container state;
- avoid disclosing credentials or unrelated container configuration;
- safely render strings supplied by an operator or Docker Engine;
- produce deterministic findings from the documented rule inputs;
- avoid adding a second service, cloud account, or telemetry channel.

The assets in scope include Docker endpoint credentials, terminal and CI log
integrity, confidential container configuration, and the integrity of the
Docker Engine and containers being inspected.

## Trust boundaries

### Docker Engine access is highly privileged

Access to a rootful Docker socket is commonly equivalent to host-level control.
DockSheriff is read-only, but the user, service account, or container running it
still possesses whatever authority the configured Docker endpoint grants.
DockSheriff cannot make an over-permissioned socket safe.

Run DockSheriff with the narrowest practical operating-system permissions. Do
not expose an unauthenticated Docker TCP endpoint to run the scanner. For a
remote Engine, use authenticated, verified TLS or another operator-controlled
secure transport. DockSheriff never enables `InsecureSkipVerify` by design.

Mounting the Docker socket into DockSheriff, if an operator chooses to do so,
creates the same underlying high-privilege trust boundary even though the
program invokes only read-only Engine methods. Protect the scanner binary and
its execution environment accordingly.

### The Engine and operator input are untrusted data sources

Container names, image references, IDs, Docker versions, endpoints, Engine
errors, and command-line values may contain control sequences, misleading
Unicode, credentials, or excessive data. Public output must sanitize and bound
these values. Endpoint display must remove user information, query parameters,
and fragments. Stable public errors should not reproduce low-level transport or
TLS errors that can contain secrets or local paths.

Sanitization reduces terminal and log injection risk; it does not make hostile
text safe for use as a shell command, HTML fragment, SQL query, or filename.

### Release and dependency supply chain

The repository depends on the Go module and GitHub Actions ecosystems. CI uses
read-only repository permissions by default and pins actions to reviewed commit
SHAs. The release configuration plans archives with checksums and SBOMs for
inspection; no published release or signed provenance should be inferred.
Checksums are not signatures. Artifact signing and verifiable provenance are
future work and must not be inferred from the v0.1 configuration.

## Allowed Engine operations

The application-level Engine interface is intentionally limited to:

- ping;
- server version;
- container list;
- container inspect.

Each call receives a fresh timeout context. Docker Info is not used because no
v0.1 rule needs it. DockSheriff must not add create, start, stop, restart, kill,
remove, update, exec, copy, pull, push, build, prune, network mutation, or volume
mutation operations.

The official SDK and HTTP transport may perform connection setup and API
version negotiation needed for these operations. DockSheriff does not contact
registries, image services, update servers, analytics systems, or any network
destination other than the configured Docker Engine endpoint. HTTP proxy
environment variables are deliberately disabled for Engine traffic so a proxy
cannot become an undeclared network destination.

Container names and IDs used for Inspect are restricted to Docker's valid name
character set before the SDK constructs the request path. An Engine-provided ID
or command-line target therefore cannot inject path separators, query data, or
a different Engine API route.

## Data handling and privacy

The official SDK decodes Docker's broad list/Inspect response types, which may
contain environment values, labels, annotations, and raw Inspect bytes. The
Docker adapter immediately projects those objects into DockSheriff-owned types
containing only the fields required by DS001-DS014. Environment values, labels,
annotations, commands, and raw JSON cannot cross the injected Engine interface
into the application or rule evaluator. Container-list IDs cross only as opaque
targets for the subsequent Inspect calls; they are not copied into findings or
reports, and the projected Inspect object has no ID field. DockSheriff never
evaluates or renders those unrelated fields and never prints a complete Inspect
response. Operators should still treat the scanner process as able to receive
sensitive Engine response bytes during SDK decoding.

The projection retains the container platform only to enforce the v0.1 Linux
rule boundary. Missing or non-Linux platform data aborts the scan instead of
being evaluated with Linux-specific assumptions.

Every Engine response body is capped at 32 MiB before SDK decoding. This bounds
one malicious response but does not make a compromised Engine trustworthy or
eliminate all resource-exhaustion risk within that limit.

Output can include sanitized container names, image references, rule
descriptions, Docker version metadata, and a redacted endpoint. These values
may still reveal operational structure, so reports should be reviewed and
redacted again before public sharing.

DockSheriff has no telemetry, cloud upload, update check, or remote policy
fetch. Files are written only when the operator explicitly redirects output or
another calling process handles it; the scanner does not maintain a report
database.

## Threats addressed

Within the documented inputs and rule semantics, DockSheriff is intended to:

- surface selected high-risk container configuration;
- detect an effectively unencrypted Docker TCP endpoint;
- avoid accidental Engine mutation through a minimal interface;
- limit hangs with per-operation deadlines;
- reduce credential disclosure and terminal/log injection in output;
- keep JSON free of ANSI styling, environment values, and arbitrary labels.

Tests use fakes and fixtures so automated validation does not require Docker or
privileged containers.

## Out of scope and known limitations

DockSheriff does not:

- scan images or packages for CVEs, malware, secrets, or provenance;
- inspect processes, files, environment values, arbitrary labels, runtime user
  IDs, Kubernetes objects, or application traffic;
- audit all Docker daemon, host kernel, filesystem, identity, network, or
  authorization settings;
- prove whether a bind source is a symlink (for example, a path resolving to the
  Docker socket) from Inspect metadata alone;
- prove that a non-numeric configured user resolves to a non-root runtime UID;
- infer Docker's daemon-wide no-new-privileges default from container Inspect;
- audit Windows container configuration in v0.1;
- determine whether all devices, capabilities, or host paths are exploitable in
  a particular workload;
- provide automatic remediation or make policy changes;
- guarantee complete detection, zero false positives, CIS compliance, or the
  security of a container, image, daemon, or host.

Rules inspect a snapshot. State can change immediately before, during, or after
a scan, and individual Inspect operations do not form an atomic Engine
snapshot. A malicious or compromised Engine can omit, falsify, or change data,
delay responses, or return inconsistent objects; DockSheriff cannot establish
the Engine's integrity.

## Relationship to other tools

DockSheriff is complementary to, not a replacement for, tools such as Trivy,
Dockle, and Docker Bench for Security. Their scopes and rule sets differ:

- image/package scanners can identify known vulnerable dependencies;
- image linters can examine build-time image practices;
- host/daemon benchmarks can inspect broader Docker host configuration;
- DockSheriff focuses on a small set of effective configuration fields for
  containers known to the selected Engine.

Use layered controls and independently review findings in the context of the
workload.

## Reporting model defects

A false negative, unsafe output path, unintended Engine method, missing timeout,
or credential leak may be security-relevant. Follow [SECURITY.md](../SECURITY.md)
and do not publish real endpoint credentials, environment values, arbitrary
labels, or complete Inspect output in a report.
