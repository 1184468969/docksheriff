# Changelog

All notable changes to DockSheriff will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project intends to use [Semantic Versioning](https://semver.org/) after
its first published release. Pre-release interfaces may still change when a
security or correctness issue requires it.

## [Unreleased]

### Added

- Initial read-only Linux container configuration scanner with `scan`,
  `inspect`, `rules`, and `explain` commands.
- Rules DS001 through DS015, table and schema-versioned JSON output, severity
  filters, ignore filters, and threshold-based exit status.
- Docker endpoint selection, API version negotiation, and verified TLS support
  through the official Docker Go SDK.
- Daemon-free tests for rule evaluation, CLI behavior, Engine failures, output
  safety, and deterministic rendering.
- Contributor, security, threat-model, rule, JSON schema, and release-preparation
  documentation.
- Hardened CI, CodeQL, dependency updates, and multi-OS CLI snapshot release
  configuration for auditing Linux containers.

### Security

- Restricted the injected Engine interface to the read-only operations needed
  by the scanner, with an independent timeout for every call.
- Projected broad SDK responses into DockSheriff-owned types that expose no
  environment, label, annotation, raw JSON, or command fields. Container-list
  IDs are used only as opaque Inspect targets and are never reported.
- Disabled HTTP proxy inheritance for Engine traffic and capped each Engine
  response body at 32 MiB.
- Rejected invalid container Inspect targets before SDK path construction and
  failed closed for non-Linux or missing-platform container data.
- Sanitized and bounded untrusted Engine and command-line strings before public
  output, and redacted Docker endpoint credentials and query data.
- Kept environment variables, arbitrary labels, and complete Inspect responses
  out of DockSheriff output.

No release has been published from this changelog yet.

[Unreleased]: https://github.com/1184468969/docksheriff/compare/main...HEAD
