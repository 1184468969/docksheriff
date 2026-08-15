# Security policy

DockSheriff is a security checking tool, but a clean DockSheriff result is not
proof that a container, image, Docker host, or deployment is secure. See the
[threat model](docs/THREAT_MODEL.md) for the intended boundary and known gaps.

## Supported versions

DockSheriff is currently pre-release software. Security reports are accepted
for the following code, without a guaranteed maintenance or response SLA:

| Version | Security reports | Fix policy |
| --- | --- | --- |
| `main` | Accepted | Considered for the next release |
| Latest published `v0.x` release or release candidate | Accepted | Best effort while it is the latest |
| Older snapshots, commits, or `v0.x` releases | Accepted for triage | No assured patch or backport |

This policy will be revised when a stable support policy exists.

## Report a vulnerability privately

Use [GitHub Private Vulnerability Reporting](https://github.com/1184468969/docksheriff/security/advisories/new)
when it is available for the repository. If that channel is unavailable, use a
private contact method listed on the repository owner's GitHub profile to ask
for a secure reporting channel. Do not include vulnerability details in the
initial contact and do not open a public vulnerability issue.

Include, after redaction:

- the affected DockSheriff version or commit;
- the operating system and Docker Engine/API versions when relevant;
- the security impact and the boundary that is crossed;
- minimal reproduction steps or a small synthetic fixture;
- whether the issue is already public or has a disclosure deadline.

Never send real passwords, tokens, private keys, registry credentials, Docker
endpoint credentials, environment variables, arbitrary labels, or complete
`docker inspect` output. Replace internal names, endpoints, image references,
container IDs, and sensitive host paths with unambiguous placeholders. If an
artifact cannot be safely redacted, ask the maintainers how to transfer it
before sending it.

## What to expect

Maintainers will handle reports according to availability. The project does
not promise a particular acknowledgement, remediation, or disclosure time.
When possible, the maintainers will confirm the affected scope, coordinate a
fix and release, and credit the reporter if requested. Please allow reasonable
time for investigation before public disclosure.

Reports about a malicious or compromised Docker Engine, output or credential
disclosure, unintended Engine methods, timeout bypasses, dependency compromise,
or release artifact integrity are especially relevant. General Docker hardening
questions and unverified scanner output are better suited to a redacted public
discussion unless they reveal a DockSheriff vulnerability.
