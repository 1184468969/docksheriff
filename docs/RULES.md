# Rule reference

DockSheriff v0.1 defines the 15 rules below. The Docker adapter projects only
the selected container-inspect fields required by DS001-DS014 into the rule
evaluator; DS015 evaluates the effective Docker endpoint and verified-TLS
configuration. They are heuristics, not proof of exploitability or safety.

The v0.1 container rules model Linux container configuration. The application
requires Inspect to identify the container platform as Linux and fails the scan
instead of applying these rules to Windows or unknown-platform data. Release
binaries may run on Linux, macOS, or Windows while connecting to a Linux Engine
or Docker Desktop in Linux-container mode.

Rule IDs and severities are stable identifiers for filtering and automation.
A future release may refine semantics to fix false positives or false negatives;
material changes will be called out in the changelog.

## Severity model

| Severity | Intended meaning |
| --- | --- |
| Critical | Configuration commonly exposes direct host or Engine control, broad host data, or unprotected Engine traffic. |
| High | Configuration substantially weakens a major isolation boundary or grants sensitive host access. |
| Medium | A recommended containment control is missing or the configured user is root. |
| Low | Reproducibility or supply-chain identity is weaker than an explicit version or valid digest. |
| Info | Reserved for future informational checks; v0.1 defines no Info rule. |

Severity is a triage aid. Workload context can raise or lower the actual risk.

## Summary

| ID | Severity | Summary |
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

## DS001: Privileged container

Triggers when `HostConfig.Privileged` is true.

Privileged mode removes or relaxes several isolation controls and can provide a
path to host compromise. Remove privileged mode and grant only the individual
capabilities and devices the workload needs. DockSheriff reports this rule once
per container and does not attempt to determine whether a particular exploit is
available.

## DS002: Docker socket mounted

Triggers for a structured bind mount whose cleaned Linux source path is exactly
`/var/run/docker.sock` or `/run/docker.sock`. A trailing slash is normalized.

The Docker socket normally grants control over the Engine and can be equivalent
to host-level authority. Remove it or place a separately reviewed, narrowly
scoped proxy between the workload and Engine.

The check uses Docker/Linux path semantics and structured Mount fields. It does
not parse raw bind strings. Inspect metadata cannot establish whether a
different source path is a symlink to the socket, so symlink aliases can be
missed.

## DS003: Host root mounted

Triggers for a structured bind mount whose cleaned Linux source is `/`.

The mount exposes the host filesystem within the permissions and propagation
mode Docker applies. Replace it with the narrowest required subdirectory and
make that mount read-only when writes are unnecessary.

## DS004: Container runtime data mounted

Triggers for a structured bind source equal to or beneath:

- `/var/lib/docker`;
- `/var/lib/containerd`;
- `/run/containerd`.

Runtime data can contain container filesystems, metadata, sockets, or
credentials. Do not mount these trees into application containers. Prefixes
such as `/var/lib/docker2` do not match.

## DS005: Sensitive host path mounted

Triggers for a structured bind source equal to or beneath `/etc`, `/root`,
`/proc`, `/sys`, `/boot`, or `/dev`, unless an earlier, more specific mount rule
applies.

These paths expose account data, kernel interfaces, devices, boot material, or
other host-sensitive data. Remove the mount or use a narrowly scoped read-only
source. Component boundaries are respected: `/etc/passwd` matches, while
`/etcetera`, `/rootless`, `/syslog`, and `/device` do not.

## DS006: Host network namespace

Triggers when Docker reports host network mode.

Host networking removes the container's separate network namespace. Prefer a
dedicated Docker network and expose only required ports. This rule does not
assess firewall policy or application-layer authentication.

## DS007: Host namespace shared

Triggers when PID, IPC, UTS, or cgroup namespace mode is `host`.

Sharing any of these host namespaces weakens isolation and can expose host
processes or resources. Use private namespaces unless the workload has a
documented need. In v0.1 the rule checks direct host sharing; a
`container:<id>` namespace shares another container rather than the host and is
outside this rule's trigger.

## DS008: Dangerous capability added

Triggers when `CapAdd` contains one of the following names, with or without the
`CAP_` prefix:

```text
SYS_ADMIN
SYS_MODULE
SYS_PTRACE
DAC_READ_SEARCH
DAC_OVERRIDE
NET_ADMIN
NET_RAW
BPF
PERFMON
CHECKPOINT_RESTORE
SYS_RAWIO
SYS_BOOT
MKNOD
```

`ALL` also triggers because it includes every capability in the explicit set;
it is a Docker aggregate value, not an additional individual capability.

These capabilities can permit sensitive kernel, network, device, or process
operations. Drop all capabilities that are not required, then add back the
minimum set. The list is intentionally explicit; DockSheriff does not claim
that every use is exploitable or that unlisted capabilities are safe.

## DS009: Mandatory security control disabled

Triggers for structured, exact security options that disable a profile:

- `seccomp=unconfined` or `seccomp:unconfined`;
- `apparmor=unconfined` or `apparmor:unconfined`;
- `label=disable` or `label:disable`;
- the legacy bare `disable` SELinux-label option.

Keys and values are compared case-insensitively after surrounding whitespace is
removed. Substrings such as `custom-seccomp=unconfined-example` do not match.
Use the runtime default or a tailored seccomp, AppArmor, or SELinux profile.

## DS010: Host device exposed

Triggers when Docker reports at least one ordinary device mapping,
`DeviceCgroupRule`, or `DeviceRequest` (including accelerator and CDI
requests).

Direct or brokered device access can expose host data or kernel interfaces.
Remove access that is not essential or use a narrowly scoped device broker.
The rule intentionally groups mappings, cgroup permission rules, and device
requests; it does not label every accelerator request as an exploit,
distinguish individual device classes, or inspect CDI device identifiers.

## DS011: Container configured to run as root

Triggers when `Config.User` is empty (Docker's configured default), `root`, a
root group form such as `root:group`, or a numeric zero form such as `0`, `0:0`,
`000`, or `+0`.

Configure a numeric non-root user and verify filesystem permissions separately.
This rule evaluates the configured user string, not the UID of a process inside
the running container. A non-numeric username cannot be resolved without
reading container identity data, which DockSheriff does not do, so the absence
of DS011 for such a name does not prove a non-root runtime UID.

## DS012: Writable root filesystem

Triggers when `HostConfig.ReadonlyRootfs` is false.

A writable root filesystem can make persistence or tampering easier. Enable
Docker's read-only root filesystem and add explicit writable mounts for the
small set of paths that need them. This rule does not inspect whether those
mounts are themselves appropriately protected.

## DS013: No explicit no-new-privileges

Triggers unless the container's security options explicitly enable
no-new-privileges. It accepts the bare `no-new-privileges` flag and the boolean
forms accepted by Moby's `strconv.ParseBool` handling, with `=` or `:` as the
separator. Repeated values are processed in order, so the last valid explicit
value wins; for example, `true,false` triggers and `false,true` does not.

This rule checks the container-level `HostConfig.SecurityOpt` returned by
Inspect. A daemon-wide no-new-privileges default can make the runtime setting
true without appearing in that slice. Because DockSheriff deliberately does
not request Docker Info, that case can produce a false positive. The rule name
and output therefore describe an absent explicit setting, not proof of the
effective runtime bit.

No-new-privileges prevents processes from gaining privileges through mechanisms
such as setuid executables. Enable it unless a documented workload requirement
prevents doing so.

## DS014: Image uses an implicit or latest tag

Triggers when the configured image reference has no tag, uses `latest` in any
letter case, or is invalid. It does not trigger for a valid digest reference or
an explicit non-latest tag. Examples include:

| Reference | Result |
| --- | --- |
| `alpine` | Finding |
| `alpine:latest` or `alpine:LATEST` | Finding |
| `registry:5000/team/image` | Finding |
| `registry:5000/team/image:1.2` | No finding |
| `image@sha256:<valid-digest>` | No finding |
| `image:tag@sha256:<valid-digest>` | No finding |
| Invalid reference | Finding |

A valid digest provides the strongest immutable identity. An explicit version
tag improves intent but can still be moved by a registry; DS014's absence for a
version tag is not a guarantee of immutability.

## DS015: Unencrypted Docker TCP endpoint

Triggers once per scan when the effective Docker endpoint is TCP-based and TLS
verification is not enabled. Unix sockets and verified TLS endpoints do not
trigger. Port numbers alone do not determine safety: `tcp://host:2376` without
TLS still triggers, while a TCP endpoint with Docker TLS verification enabled
does not.

Use a local socket, authenticated secure transport, or verified TLS. Endpoint
credentials, query parameters, and fragments are redacted from display and
errors. DockSheriff never enables insecure certificate verification.

## Filtering and interpretation

Use `--ignore RULE` only after reviewing and documenting why the rule is
acceptable for that workload. `--min-severity` controls what human output
expands; it does not change the findings included in summaries or JSON.
`--fail-on` sets the severity threshold for exit status 1.

Rules can produce false positives and false negatives. If a boundary is wrong,
submit a minimal synthetic example using the false-positive issue form. Never
post complete Inspect output, environment values, arbitrary labels, endpoint
credentials, or other secrets.
