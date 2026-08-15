package audit

import (
	_ "crypto/sha256"
	"path"
	"strconv"
	"strings"

	"github.com/1184468969/docksheriff/internal/docker"
	"github.com/1184468969/docksheriff/internal/safe"
	"github.com/distribution/reference"
)

// Rules is ordered by stable rule ID.
var Rules = []Rule{
	{"DS001", Critical, "Privileged container", "Privileged containers can bypass most isolation controls.", "Remove --privileged and grant only required capabilities."},
	{"DS002", Critical, "Docker socket mounted", "The Docker socket normally grants host-level control.", "Remove the socket mount or use a narrowly scoped proxy."},
	{"DS003", Critical, "Host root mounted", "Mounting / exposes the entire host filesystem.", "Mount only the required directory, preferably read-only."},
	{"DS004", Critical, "Container runtime data mounted", "Runtime state may expose credentials and permit host compromise.", "Do not mount container runtime data directories."},
	{"DS005", High, "Sensitive host path mounted", "Sensitive host paths expose kernel, device, boot, or account data.", "Remove the mount or replace it with a narrow read-only mount."},
	{"DS006", High, "Host network namespace", "Host networking removes network isolation.", "Use a dedicated bridge network."},
	{"DS007", High, "Host namespace shared", "Sharing host namespaces weakens process and host isolation.", "Use private PID, IPC, UTS, and cgroup namespaces."},
	{"DS008", High, "Dangerous capability added", "Powerful Linux capabilities can enable container escape or host tampering.", "Drop capabilities and add only the minimum required."},
	{"DS009", High, "Mandatory security control disabled", "Disabling seccomp, AppArmor, or SELinux removes defense in depth.", "Use the runtime default or a tailored security profile."},
	{"DS010", High, "Host device exposed", "Direct or brokered host device access can expose host data or kernel interfaces.", "Remove device access or use a narrowly scoped broker."},
	{"DS011", Medium, "Container configured to run as root", "A configured root user increases the impact of a container breakout.", "Configure a numeric non-root USER and verify the runtime process identity separately."},
	{"DS012", Medium, "Writable root filesystem", "A writable root filesystem aids persistence and tampering.", "Enable --read-only and add explicit writable mounts."},
	{"DS013", Medium, "No explicit no-new-privileges", "Processes may gain additional privileges through setuid binaries.", "Set security-opt=no-new-privileges:true."},
	{"DS014", Low, "Image uses an implicit or latest tag", "Implicit and latest tags can change unexpectedly.", "Pin the image by a valid digest or use an explicit version tag."},
	{"DS015", Critical, "Unencrypted Docker TCP endpoint", "Credentials and Engine traffic can be intercepted or modified.", "Use a local socket, SSH, or TLS-verified TCP endpoint."},
}

var dangerousCapabilities = map[string]struct{}{
	"SYS_ADMIN":          {},
	"SYS_MODULE":         {},
	"SYS_PTRACE":         {},
	"DAC_READ_SEARCH":    {},
	"DAC_OVERRIDE":       {},
	"NET_ADMIN":          {},
	"NET_RAW":            {},
	"BPF":                {},
	"PERFMON":            {},
	"CHECKPOINT_RESTORE": {},
	"SYS_RAWIO":          {},
	"SYS_BOOT":           {},
	"MKNOD":              {},
}

// Evaluate checks the structured, privacy-minimized Engine projection.
func Evaluate(inspect docker.Container) []Finding {
	if inspect.Config == nil || inspect.HostConfig == nil {
		return nil
	}
	name := safe.Text(strings.TrimPrefix(inspect.Name, "/"))
	image := safe.Text(inspect.Config.Image)
	host := inspect.HostConfig
	var findings []Finding
	add := func(id string) { findings = append(findings, makeFinding(id, name, image)) }

	if host.Privileged {
		add("DS001")
	}
	for _, source := range inspect.BindMountSources {
		checkLinuxMount(source, add)
	}
	if host.NetworkMode == "host" {
		add("DS006")
	}
	if host.PIDMode == "host" || host.IPCMode == "host" || host.UTSMode == "host" || host.CgroupNamespaceMode == "host" {
		add("DS007")
	}
	for _, capability := range host.CapabilitiesAdded {
		capability = strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(capability)), "CAP_")
		if capability == "ALL" {
			add("DS008")
			break
		}
		if _, found := dangerousCapabilities[capability]; found {
			add("DS008")
			break
		}
	}

	noNewPrivileges := false
	for _, option := range host.SecurityOptions {
		key, value, hasValue := securityOption(option)
		if (key == "seccomp" || key == "apparmor") && hasValue && value == "unconfined" {
			add("DS009")
		}
		if (key == "label" && hasValue && value == "disable") || (key == "disable" && !hasValue) {
			add("DS009")
		}
		if key == "no-new-privileges" {
			if !hasValue {
				noNewPrivileges = true
				continue
			}
			if parsed, err := strconv.ParseBool(value); err == nil {
				// Moby processes repeated options in order, so the last valid
				// no-new-privileges value is the effective container override.
				noNewPrivileges = parsed
			}
		}
	}
	if host.HasDeviceAccess {
		add("DS010")
	}
	if configuredRoot(inspect.Config.User) {
		add("DS011")
	}
	if !host.ReadonlyRootFilesystem {
		add("DS012")
	}
	if !noNewPrivileges {
		add("DS013")
	}
	if mutableImageReference(inspect.Config.Image) {
		add("DS014")
	}
	return unique(findings)
}

// EndpointFinding creates the non-container DS015 finding.
func EndpointFinding() Finding { return makeFinding("DS015", "", "") }

// EvaluateEndpoint applies DS015 to effective connection metadata.
func EvaluateEndpoint(insecureTCP bool) []Finding {
	if !insecureTCP {
		return []Finding{}
	}
	return []Finding{EndpointFinding()}
}

func makeFinding(id, name, image string) Finding {
	rule, err := Explain(id)
	if err != nil {
		panic("invalid built-in rule ID")
	}
	return Finding{
		RuleID:      rule.ID,
		Severity:    SeverityJSON(rule.Severity),
		Container:   safe.Text(name),
		Image:       safe.Text(image),
		Summary:     rule.Summary,
		Risk:        rule.Risk,
		Remediation: rule.Remediation,
	}
}

func checkLinuxMount(source string, add func(string)) {
	if !strings.HasPrefix(source, "/") {
		return
	}
	cleaned := path.Clean(source)
	switch {
	case cleaned == "/var/run/docker.sock" || cleaned == "/run/docker.sock":
		add("DS002")
	case cleaned == "/":
		add("DS003")
	case withinLinuxPath(cleaned, "/var/lib/docker") ||
		withinLinuxPath(cleaned, "/var/lib/containerd") ||
		withinLinuxPath(cleaned, "/run/containerd"):
		add("DS004")
	case sensitiveLinuxPath(cleaned):
		add("DS005")
	}
}

func withinLinuxPath(value, base string) bool {
	return value == base || strings.HasPrefix(value, base+"/")
}

func sensitiveLinuxPath(value string) bool {
	for _, base := range []string{"/etc", "/root", "/proc", "/sys", "/boot", "/dev"} {
		if withinLinuxPath(value, base) {
			return true
		}
	}
	return false
}

func securityOption(option string) (key, value string, hasValue bool) {
	option = strings.TrimSpace(strings.ToLower(option))
	index := strings.IndexAny(option, "=:")
	if index < 0 {
		return option, "", false
	}
	return strings.TrimSpace(option[:index]), strings.TrimSpace(option[index+1:]), true
}

func configuredRoot(user string) bool {
	user = strings.TrimSpace(user)
	name, _, _ := strings.Cut(user, ":")
	if name == "" || name == "root" {
		return true
	}
	name = strings.TrimPrefix(name, "+")
	if name == "" {
		return false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return false
		}
	}
	uid, err := strconv.ParseUint(name, 10, 64)
	return err == nil && uid == 0
}

func mutableImageReference(image string) bool {
	named, err := reference.ParseNormalizedNamed(strings.TrimSpace(image))
	if err != nil {
		return true
	}
	if _, pinned := named.(reference.Digested); pinned {
		return false
	}
	if reference.IsNameOnly(named) {
		return true
	}
	tagged, ok := named.(reference.NamedTagged)
	return !ok || strings.EqualFold(tagged.Tag(), "latest")
}

func unique(input []Finding) []Finding {
	seen := make(map[string]struct{}, len(input))
	output := make([]Finding, 0, len(input))
	for _, item := range input {
		if _, found := seen[item.RuleID]; found {
			continue
		}
		seen[item.RuleID] = struct{}{}
		output = append(output, item)
	}
	return output
}
