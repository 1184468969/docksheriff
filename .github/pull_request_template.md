# Pull request

## Summary

<!-- Explain the problem and the smallest behavior change that solves it. -->

## Security and privacy impact

<!-- Describe Engine methods, data read, output, endpoint handling, timeouts, and dependency changes. State "none" only after reviewing them. -->

## Validation

<!-- List exact commands and results. Tests must not require Docker or privileged containers. -->

- [ ] `gofmt -w $(find . -name '*.go' -type f)`
- [ ] `go test ./...`
- [ ] `go test -race ./...`
- [ ] `go vet ./...`
- [ ] `go build ./cmd/docksheriff`
- [ ] `golangci-lint run`
- [ ] `govulncheck ./...`
- [ ] `git diff --check`

## Safety checklist

- [ ] The Engine surface remains limited to ping, server version, container list, and container inspect.
- [ ] This change adds no Docker mutation, exec/cp, environment or arbitrary-label access/output, full Inspect output, telemetry, update check, cloud upload, or non-Engine network access.
- [ ] Every Engine call has its own timeout context.
- [ ] All variable Engine, error, and argument text reaching output is sanitized, redacted where needed, and length-limited.
- [ ] Tests use fakes/fixtures and need neither a Docker daemon nor privileged containers.
- [ ] Public examples contain no credentials, environment variables, arbitrary labels, complete Inspect JSON, private image names, internal endpoints, or sensitive paths.
- [ ] Rule, JSON schema, threat-model, README, changelog, and release-note changes are included when relevant.

## Compatibility

<!-- Note CLI, JSON schema, rule semantic, exit-code, Go/platform, or release artifact changes. -->
