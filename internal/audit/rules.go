package audit

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/1184468969/docksheriff/internal/dockerapi"
)

type Rule struct {
	ID                         string
	Severity                   Severity
	Summary, Risk, Remediation string
}

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
	{"DS010", High, "Host device mapped", "Direct device access can expose host data or kernel interfaces.", "Remove device mappings or use a safer broker."},
	{"DS011", Medium, "Container runs as root", "Root in a container increases the impact of a breakout.", "Set a numeric non-root USER."},
	{"DS012", Medium, "Writable root filesystem", "A writable root filesystem aids persistence and tampering.", "Enable --read-only and add explicit writable mounts."},
	{"DS013", Medium, "No-new-privileges not enabled", "Processes may gain additional privileges through setuid binaries.", "Set security-opt=no-new-privileges:true."},
	{"DS014", Low, "Image is not immutably identified", "latest or an implicit tag can change unexpectedly.", "Pin the image by digest or an explicit version tag."},
	{"DS015", Critical, "Unencrypted Docker TCP endpoint", "Credentials and Engine traffic can be intercepted or modified.", "Use a Unix socket, SSH, or TLS-verified TCP endpoint."},
}

func rule(id string) Rule {
	for _, r := range Rules {
		if r.ID == id {
			return r
		}
	}
	panic(id)
}
func finding(id, name, image string) Finding {
	r := rule(id)
	return Finding{r.ID, SeverityJSON(r.Severity), Sanitize(name), Sanitize(image), r.Summary, r.Risk, r.Remediation}
}

func Evaluate(name, image string, c *dockerapi.ContainerConfig, h *dockerapi.HostConfig) []Finding {
	if c == nil || h == nil {
		return nil
	}
	var out []Finding
	add := func(id string) { out = append(out, finding(id, name, image)) }
	if h.Privileged {
		add("DS001")
	}
	for _, m := range h.Mounts {
		if strings.EqualFold(m.Type, "bind") {
			checkMount(m.Source, add)
		}
	}
	for _, b := range h.Binds {
		src := strings.SplitN(b, ":", 2)[0]
		checkMount(src, add)
	}
	if h.NetworkMode == "host" {
		add("DS006")
	}
	if h.PidMode == "host" || h.IpcMode == "host" || h.UTSMode == "host" || h.CgroupnsMode == "host" {
		add("DS007")
	}
	danger := map[string]bool{"SYS_ADMIN": true, "SYS_MODULE": true, "SYS_PTRACE": true, "DAC_READ_SEARCH": true, "NET_ADMIN": true, "BPF": true, "PERFMON": true}
	for _, cap := range h.CapAdd {
		if danger[strings.TrimPrefix(strings.ToUpper(cap), "CAP_")] {
			add("DS008")
			break
		}
	}
	nnp := false
	for _, o := range h.SecurityOpt {
		l := strings.ToLower(o)
		if strings.Contains(l, "seccomp=unconfined") || strings.Contains(l, "apparmor=unconfined") || strings.Contains(l, "label=disable") {
			add("DS009")
		}
		if l == "no-new-privileges" || l == "no-new-privileges=true" {
			nnp = true
		}
	}
	if len(h.Devices) > 0 {
		add("DS010")
	}
	user := strings.ToLower(strings.TrimSpace(c.User))
	if user == "" || user == "0" || user == "root" || strings.HasPrefix(user, "0:") || strings.HasPrefix(user, "root:") {
		add("DS011")
	}
	if !h.ReadonlyRootfs {
		add("DS012")
	}
	if !nnp {
		add("DS013")
	}
	if unpinned(image) {
		add("DS014")
	}
	return unique(out)
}

func checkMount(src string, add func(string)) {
	p := filepath.Clean(src)
	switch {
	case p == "/var/run/docker.sock" || p == "/run/docker.sock":
		add("DS002")
	case p == "/":
		add("DS003")
	case within(p, "/var/lib/docker") || within(p, "/var/lib/containerd") || within(p, "/run/containerd"):
		add("DS004")
	case sensitive(p):
		add("DS005")
	}
}
func within(p, base string) bool {
	return p == base || strings.HasPrefix(p, base+string(filepath.Separator))
}
func sensitive(p string) bool {
	for _, b := range []string{"/etc", "/root", "/proc", "/sys", "/boot", "/dev"} {
		if within(p, b) {
			return true
		}
	}
	return false
}
func unpinned(s string) bool {
	if strings.Contains(s, "@sha256:") {
		return false
	}
	last := s[strings.LastIndex(s, "/")+1:]
	return !strings.Contains(last, ":") || strings.HasSuffix(last, ":latest")
}
func unique(in []Finding) []Finding {
	seen := map[string]bool{}
	out := in[:0]
	for _, f := range in {
		if !seen[f.ID] {
			seen[f.ID] = true
			out = append(out, f)
		}
	}
	return out
}
func Explain(id string) (Rule, error) {
	id = strings.ToUpper(id)
	for _, r := range Rules {
		if r.ID == id {
			return r, nil
		}
	}
	return Rule{}, fmt.Errorf("unknown rule %q", id)
}
