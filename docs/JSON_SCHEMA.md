# JSON schema version 1

`docksheriff --format json` writes one UTF-8 JSON object followed by a newline.
The top-level `schema_version` value is `"1"`. Consumers should reject an
unknown major schema version or handle it explicitly rather than assuming new
fields or types have the same meaning.

The schema is a public compatibility contract for v0.1 releases. Fields may be
added in a backward-compatible release, but existing field names, JSON types,
and documented meanings should not change without a schema-version change.

## Example

The following values are illustrative and sanitized. It represents three
findings so the summary invariants are visible:

```json
{
  "schema_version": "1",
  "generated_at": "2026-08-13T07:00:00Z",
  "docker": {
    "endpoint": "unix:///var/run/docker.sock",
    "server_version": "28.5.2",
    "api_version": "1.51"
  },
  "scanned_containers": 1,
  "summary": {
    "critical": 1,
    "high": 0,
    "medium": 1,
    "low": 1,
    "info": 0,
    "total": 3
  },
  "findings": [
    {
      "rule_id": "DS002",
      "severity": "critical",
      "container": "example",
      "image": "example/app:1.2.3",
      "summary": "Docker socket mounted",
      "risk": "The Docker socket normally grants host-level control.",
      "remediation": "Remove the socket mount or use a narrowly scoped proxy."
    },
    {
      "rule_id": "DS011",
      "severity": "medium",
      "container": "example",
      "image": "example/app:1.2.3",
      "summary": "Container configured to run as root",
      "risk": "A configured root user increases the impact of a container breakout.",
      "remediation": "Configure a numeric non-root USER and verify the runtime process identity separately."
    },
    {
      "rule_id": "DS014",
      "severity": "low",
      "container": "example-worker",
      "image": "example/worker:latest",
      "summary": "Image uses an implicit or latest tag",
      "risk": "Implicit and latest tags can change unexpectedly.",
      "remediation": "Pin the image by a valid digest or use an explicit version tag."
    }
  ]
}
```

## Top-level fields

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `schema_version` | string | Yes | JSON contract version; exactly `"1"` for this document. |
| `generated_at` | string | Yes | UTC RFC 3339 timestamp, truncated to whole seconds, generated after the scan. |
| `docker` | object | Yes | Sanitized metadata for the effective Engine connection. |
| `scanned_containers` | integer | Yes | Number of container Inspect operations represented by the successful report. |
| `summary` | object | Yes | Counts for all non-ignored findings. |
| `findings` | array | Yes | Complete, deterministically ordered list; an empty result is `[]`, never `null`. |

A report is emitted only after the scan succeeds. Connection, argument,
inspection, and output errors use exit status 2 and are written as bounded,
sanitized text to stderr; they are not encoded as schema-1 report objects.
Non-Linux or missing-platform Inspect data is an inspection error: it returns
status 2 and produces no schema-1 report.

## `docker`

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `endpoint` | string | Yes | Effective endpoint with username, password, query, and fragment removed. |
| `server_version` | string | Yes | Sanitized Docker server version returned by the Engine, or `"unknown"` if absent. |
| `api_version` | string | Yes | Sanitized API version returned by the Engine, or `"unknown"` if absent. |

Endpoint redaction prevents common credential disclosure; it does not make the
remaining hostname or socket path non-sensitive. Review reports before sharing
them publicly. Metadata strings are length-limited and stripped of terminal
controls and bidirectional control characters.

## `summary`

The object always contains the integer fields `critical`, `high`, `medium`,
`low`, `info`, and `total`, including zero values. Counts reflect findings after
all `--ignore` filters. `--min-severity` changes human expansion only and does
not remove JSON findings. `--fail-on` changes exit status only and does not
remove findings.

For a valid report:

```text
total = critical + high + medium + low + info = len(findings)
```

## Finding object

Every element of `findings` contains all fields below. `container` and `image`
are empty strings for an endpoint-level DS015 finding; fields are not omitted.

| Field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `rule_id` | string | Yes | Stable identifier `DS001` through `DS015`. |
| `severity` | string | Yes | One of `critical`, `high`, `medium`, `low`, or `info`. |
| `container` | string | Yes | Sanitized container name, or `""` for a non-container finding. |
| `image` | string | Yes | Sanitized configured image reference, or `""` for a non-container finding. |
| `summary` | string | Yes | Stable short rule description. |
| `risk` | string | Yes | Explanation of why the configuration can be risky. |
| `remediation` | string | Yes | Read-only remediation guidance; DockSheriff does not apply it. |

The JSON report never contains ANSI color styling. Container and image strings
are derived from Engine data but sanitized and length-limited. DockSheriff does
not include environment variables, arbitrary labels, full Inspect responses, or
Docker endpoint credentials. It does not include a full container ID.

## Ordering

Findings use this deterministic ascending/descending key sequence:

1. severity descending: Critical, High, Medium, Low, Info;
2. sanitized container name ascending, compared case-insensitively;
3. sanitized container name ascending as a case-sensitive tie breaker;
4. rule ID ascending.

DS015 has an empty container name, so among Critical findings it sorts according
to the same empty-string rule. Container scan order from the daemon does not
change JSON order. If two findings otherwise have identical sort keys, their
relative order follows the stable input order; normal rule evaluation emits at
most one finding for a given rule and container.

## Time and reproducibility

`generated_at` intentionally records report creation time, so byte-for-byte
output differs between ordinary runs. Tests inject a fixed clock for golden
files. Consumers that need a content comparison should parse the JSON and
exclude `generated_at` deliberately rather than depending on local time format.

## Error and privacy boundaries

All Engine-provided strings are untrusted. JSON string escaping, sanitization,
redaction, and length limits reduce output-injection and terminal-denial risks.
Consumers must still treat every string as data and must not place values into a
shell command, HTML, SQL, or a filesystem path without context-appropriate
handling.

See [docs/THREAT_MODEL.md](THREAT_MODEL.md) for the broader trust boundary and
[docs/RULES.md](RULES.md) for rule semantics.
