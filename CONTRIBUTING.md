# Contributing to DockSheriff

Thank you for helping improve DockSheriff. Changes are welcome when they keep
the project small, testable, and safe to run against a Docker Engine.

By participating, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
Security vulnerabilities should be reported through the private process in
[SECURITY.md](SECURITY.md), not through a public issue.

## Safety boundaries

Every contribution must preserve these invariants:

- Docker access is read-only and limited to ping, server version, container
  list, and container inspect.
- Do not add create, start, stop, restart, kill, remove, update, exec, copy,
  pull, push, build, prune, network mutation, or volume mutation operations.
- Do not access or render container environment variables, arbitrary labels,
  or complete Inspect responses.
- Do not add telemetry, update checks, cloud uploads, or network access other
  than the Docker Engine endpoint selected by the operator.
- Treat command-line values and every Engine-provided string or error as
  untrusted. Sanitize, redact, and length-limit public output.
- Give every Engine operation its own timeout context.
- Tests must not require a Docker daemon, a Docker socket, privileged
  containers, or elevated host permissions.

If a proposed feature needs to cross one of these boundaries, discuss it with
the maintainers before writing code. It may be outside DockSheriff's scope.

## Reporting a bug or false positive

Use the matching issue form. Provide the smallest redacted example that can
reproduce the problem. Never paste:

- passwords, tokens, private keys, or Docker endpoint credentials;
- environment variables or arbitrary labels;
- full `docker inspect` output;
- private image names, registry credentials, internal hostnames, or sensitive
  filesystem paths unless they have been replaced with safe placeholders.

Prefer a minimal configuration fragment that contains only fields needed by
the affected rule. If you are unsure whether a report is sensitive, use the
private security-reporting process.

## Development workflow

DockSheriff requires the Go version declared in `go.mod` (currently Go 1.24) or
newer. Fork the repository, create a focused branch, and keep unrelated changes
out of the pull request.

Before submitting a change, run:

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

The last two tools are also run by CI. Install them from their official
projects and use the versions selected by the workflow.

Release-related changes should additionally run:

```sh
goreleaser check
goreleaser release --snapshot --clean
```

The `v0.1.0-rc.1` readiness workflow was validated with GoReleaser v2.12.0 and
Syft v1.33.0. Rebuild and validate a snapshot from every exact candidate commit,
and record and review any intentional tool upgrade before relying on new
evidence.

A snapshot release is a local verification step; do not publish its artifacts
as an official release.

## Tests and rule changes

Use fakes and fixtures instead of a live Engine. Tests should be deterministic
and should cover errors, cancellation, timeouts, and hostile strings as well as
the successful path.

A new or changed rule needs:

- a narrowly stated risk and remediation;
- positive, negative, boundary, and duplicate-suppression tests;
- fixture fields limited to the configuration needed by the rule;
- an update to [docs/RULES.md](docs/RULES.md);
- an assessment of JSON/output compatibility and false-positive risk.

Do not silently broaden an existing rule. Rule IDs and documented semantics
are part of the public interface.

## Pull requests

Pull requests should explain the problem, the chosen behavior, security and
privacy impact, and exact validation performed. Documentation-only changes can
mark inapplicable checks accordingly. Maintainers may ask for a smaller change
or more evidence before merging.

Unless explicitly stated otherwise, submitted contributions are provided under
the [Apache License 2.0](LICENSE).
