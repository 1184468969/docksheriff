package audit

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"

	"github.com/1184468969/docksheriff/internal/docker"
)

const validDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRulesPositiveNegativeAndBoundaryCases(t *testing.T) {
	tests := []struct {
		id       string
		positive func(*container.InspectResponse)
		negative func(*container.InspectResponse)
		boundary func(*container.InspectResponse)
	}{
		{
			id:       "DS001",
			positive: func(value *container.InspectResponse) { value.HostConfig.Privileged = true },
			negative: func(value *container.InspectResponse) { value.HostConfig.Privileged = false },
			boundary: func(value *container.InspectResponse) { value.HostConfig.Privileged = true; value.Config.User = "1000" },
		},
		{
			id:       "DS002",
			positive: bind("/var/run/docker.sock"),
			negative: volume("/var/run/docker.sock"),
			boundary: bind("/run/docker.sock/"),
		},
		{
			id:       "DS003",
			positive: bind("/"),
			negative: volume("/"),
			boundary: bind("/tmp/.."),
		},
		{
			id:       "DS004",
			positive: bind("/var/lib/docker"),
			negative: bind("/var/lib/docker2"),
			boundary: bind("/run/containerd/io.containerd.runtime.v2.task"),
		},
		{
			id:       "DS005",
			positive: bind("/etc/passwd"),
			negative: bind("/etcetera"),
			boundary: bind("/dev/../proc/sys"),
		},
		{
			id:       "DS006",
			positive: func(value *container.InspectResponse) { value.HostConfig.NetworkMode = "host" },
			negative: func(value *container.InspectResponse) { value.HostConfig.NetworkMode = "private" },
			boundary: func(value *container.InspectResponse) { value.HostConfig.NetworkMode = "container:abc" },
		},
		{
			id:       "DS007",
			positive: func(value *container.InspectResponse) { value.HostConfig.PidMode = "host" },
			negative: func(value *container.InspectResponse) { value.HostConfig.PidMode = "private" },
			boundary: func(value *container.InspectResponse) { value.HostConfig.PidMode = "container:abc" },
		},
		{
			id:       "DS008",
			positive: func(value *container.InspectResponse) { value.HostConfig.CapAdd = []string{"CAP_SYS_ADMIN"} },
			negative: func(value *container.InspectResponse) { value.HostConfig.CapAdd = []string{"CHOWN"} },
			boundary: func(value *container.InspectResponse) { value.HostConfig.CapAdd = []string{"mknod"} },
		},
		{
			id: "DS009",
			positive: func(value *container.InspectResponse) {
				value.HostConfig.SecurityOpt = []string{"seccomp=unconfined", "no-new-privileges=true"}
			},
			negative: func(value *container.InspectResponse) {
				value.HostConfig.SecurityOpt = []string{"seccomp=default", "no-new-privileges=true"}
			},
			boundary: func(value *container.InspectResponse) {
				value.HostConfig.SecurityOpt = []string{"custom-seccomp=unconfined-example", "no-new-privileges=true"}
			},
		},
		{
			id: "DS010",
			positive: func(value *container.InspectResponse) {
				value.HostConfig.Devices = []container.DeviceMapping{{PathOnHost: "/dev/kvm"}}
			},
			negative: func(value *container.InspectResponse) {},
			boundary: func(value *container.InspectResponse) {
				value.HostConfig.DeviceRequests = []container.DeviceRequest{{Driver: "cdi", DeviceIDs: []string{"vendor.example/device=one"}}}
			},
		},
		{
			id:       "DS011",
			positive: func(value *container.InspectResponse) { value.Config.User = "root:group" },
			negative: func(value *container.InspectResponse) { value.Config.User = "app" },
			boundary: func(value *container.InspectResponse) { value.Config.User = "+000:1000" },
		},
		{
			id:       "DS012",
			positive: func(value *container.InspectResponse) { value.HostConfig.ReadonlyRootfs = false },
			negative: func(value *container.InspectResponse) { value.HostConfig.ReadonlyRootfs = true },
			boundary: func(value *container.InspectResponse) {
				value.HostConfig.ReadonlyRootfs = false
				value.HostConfig.Mounts = []mount.Mount{{Type: mount.TypeTmpfs, Target: "/tmp"}}
			},
		},
		{
			id: "DS013",
			positive: func(value *container.InspectResponse) {
				value.HostConfig.SecurityOpt = []string{"no-new-privileges:false"}
			},
			negative: func(value *container.InspectResponse) {
				value.HostConfig.SecurityOpt = []string{"no-new-privileges=true"}
			},
			boundary: func(value *container.InspectResponse) { value.HostConfig.SecurityOpt = []string{"no-new-privileges"} },
		},
		{
			id:       "DS014",
			positive: func(value *container.InspectResponse) { value.Config.Image = "alpine" },
			negative: func(value *container.InspectResponse) { value.Config.Image = "registry:5000/team/image:1.2" },
			boundary: func(value *container.InspectResponse) { value.Config.Image = "image@" + validDigest },
		},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			positive := safeInspectFixture()
			tt.positive(&positive)
			if !hasRule(evaluate(positive), tt.id) {
				t.Fatalf("positive case did not produce %s: %#v", tt.id, evaluate(positive))
			}

			negative := safeInspectFixture()
			tt.negative(&negative)
			if hasRule(evaluate(negative), tt.id) {
				t.Fatalf("negative case produced %s: %#v", tt.id, evaluate(negative))
			}

			boundary := safeInspectFixture()
			tt.boundary(&boundary)
			gotBoundary := hasRule(evaluate(boundary), tt.id)
			// Boundary functions are chosen to exercise both normalized-positive
			// and lookalike-negative values. Assert the documented expectation.
			wantBoundary := map[string]bool{
				"DS001": true, "DS002": true, "DS003": true, "DS004": true,
				"DS005": true, "DS006": false, "DS007": false, "DS008": true,
				"DS009": false, "DS010": true, "DS011": true, "DS012": true,
				"DS013": false, "DS014": false,
			}[tt.id]
			if gotBoundary != wantBoundary {
				t.Fatalf("boundary %s got=%v findings=%#v", tt.id, gotBoundary, evaluate(boundary))
			}
		})
	}
}

func TestDS015PositiveNegativeBoundaryAndDuplicateSuppression(t *testing.T) {
	if got := EvaluateEndpoint(true); len(got) != 1 || got[0].RuleID != "DS015" {
		t.Fatalf("positive=%#v", got)
	}
	if got := EvaluateEndpoint(false); len(got) != 0 {
		t.Fatalf("negative=%#v", got)
	}
	// DS015 is one connection-level finding, not one finding per container.
	if got := unique(append(EvaluateEndpoint(true), EvaluateEndpoint(true)...)); len(got) != 1 {
		t.Fatalf("duplicate suppression=%#v", got)
	}
	if finding := EndpointFinding(); finding.Container != "" || finding.Image != "" {
		t.Fatalf("connection finding leaked container fields: %#v", finding)
	}
}

func TestEveryRuleSuppressesDuplicates(t *testing.T) {
	fixture := safeInspectFixture()
	fixture.HostConfig.Privileged = true
	fixture.Mounts = []container.MountPoint{
		{Type: mount.TypeBind, Source: "/var/run/docker.sock"},
		{Type: mount.TypeBind, Source: "/var/run/docker.sock/"},
		{Type: mount.TypeBind, Source: "/"},
		{Type: mount.TypeBind, Source: "/tmp/.."},
		{Type: mount.TypeBind, Source: "/var/lib/docker"},
		{Type: mount.TypeBind, Source: "/var/lib/docker/containers"},
		{Type: mount.TypeBind, Source: "/etc"},
		{Type: mount.TypeBind, Source: "/etc/passwd"},
	}
	fixture.HostConfig.Mounts = append([]mount.Mount(nil),
		mount.Mount{Type: mount.TypeBind, Source: "/var/run/docker.sock"},
		mount.Mount{Type: mount.TypeBind, Source: "/"},
		mount.Mount{Type: mount.TypeBind, Source: "/var/lib/containerd"},
		mount.Mount{Type: mount.TypeBind, Source: "/proc"},
	)
	fixture.HostConfig.NetworkMode = "host"
	fixture.HostConfig.PidMode = "host"
	fixture.HostConfig.IpcMode = "host"
	fixture.HostConfig.UTSMode = "host"
	fixture.HostConfig.CgroupnsMode = "host"
	fixture.HostConfig.CapAdd = []string{"SYS_ADMIN", "CAP_SYS_MODULE"}
	fixture.HostConfig.SecurityOpt = []string{
		"seccomp=unconfined", "apparmor:unconfined", "label=disable", "no-new-privileges=false",
	}
	fixture.HostConfig.Devices = []container.DeviceMapping{{PathOnHost: "/dev/kvm"}, {PathOnHost: "/dev/fuse"}}
	fixture.HostConfig.DeviceCgroupRules = []string{"c 10:232 rwm"}
	fixture.HostConfig.DeviceRequests = []container.DeviceRequest{{Driver: "cdi"}}
	fixture.Config.User = "root"
	fixture.HostConfig.ReadonlyRootfs = false
	fixture.Config.Image = "alpine:latest"

	findings := evaluate(fixture)
	counts := map[string]int{}
	for _, finding := range findings {
		counts[finding.RuleID]++
	}
	for index := 1; index <= 14; index++ {
		id := fmt.Sprintf("DS%03d", index)
		if counts[id] != 1 {
			t.Errorf("%s count=%d findings=%#v", id, counts[id], findings)
		}
	}
}

func TestLinuxMountPathMatrix(t *testing.T) {
	tests := []struct {
		source, want string
	}{
		{"/var/run/docker.sock", "DS002"},
		{"/var/run/docker.sock/", "DS002"},
		{"/run/docker.sock", "DS002"},
		{"/", "DS003"},
		{"/etc", "DS005"},
		{"/etc/passwd", "DS005"},
		{"/etcetera", ""},
		{"/root", "DS005"},
		{"/rootless", ""},
		{"/proc", "DS005"},
		{"/proc/sys", "DS005"},
		{"/sys", "DS005"},
		{"/syslog", ""},
		{"/boot", "DS005"},
		{"/dev", "DS005"},
		{"/device", ""},
		{"/var/lib/docker", "DS004"},
		{"/var/lib/docker2", ""},
		{"/var/lib/containerd", "DS004"},
		{"/run/containerd", "DS004"},
		{`C:\\var\\run\\docker.sock`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			fixture := safeInspectFixture()
			fixture.Mounts = []container.MountPoint{{Type: mount.TypeBind, Source: tt.source}}
			findings := evaluate(fixture)
			if tt.want == "" && len(findings) != 0 {
				t.Fatalf("unexpected findings=%#v", findings)
			}
			if tt.want != "" && (!hasRule(findings, tt.want) || len(findings) != 1) {
				t.Fatalf("findings=%#v want=%s", findings, tt.want)
			}
		})
	}
}

func TestRawBindsAreNotParsed(t *testing.T) {
	fixture := safeInspectFixture()
	fixture.HostConfig.Binds = []string{
		"/var/run/docker.sock:/sock",
		`C:\\data:/data`,
	}
	if findings := evaluate(fixture); len(findings) != 0 {
		t.Fatalf("raw bind strings produced findings: %#v", findings)
	}
}

func TestNamespaceModesAndActualCaseSemantics(t *testing.T) {
	tests := []struct {
		name, network, pid, ipc, uts, cgroup string
		wantDS006, wantDS007                 bool
	}{
		{"host", "host", "host", "", "", "", true, true},
		{"container", "container:abc", "container:abc", "container:abc", "", "", false, false},
		{"private", "private", "private", "private", "private", "private", false, false},
		{"empty", "", "", "", "", "", false, false},
		{"case-sensitive", "HOST", "HOST", "HOST", "HOST", "HOST", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := safeInspectFixture()
			fixture.HostConfig.NetworkMode = container.NetworkMode(tt.network)
			fixture.HostConfig.PidMode = container.PidMode(tt.pid)
			fixture.HostConfig.IpcMode = container.IpcMode(tt.ipc)
			fixture.HostConfig.UTSMode = container.UTSMode(tt.uts)
			fixture.HostConfig.CgroupnsMode = container.CgroupnsMode(tt.cgroup)
			findings := evaluate(fixture)
			if hasRule(findings, "DS006") != tt.wantDS006 || hasRule(findings, "DS007") != tt.wantDS007 {
				t.Fatalf("findings=%#v", findings)
			}
		})
	}
}

func TestDangerousCapabilityListMatchesDocumentedSet(t *testing.T) {
	want := []string{
		"SYS_ADMIN", "SYS_MODULE", "SYS_PTRACE", "DAC_READ_SEARCH", "DAC_OVERRIDE",
		"NET_ADMIN", "NET_RAW", "BPF", "PERFMON", "CHECKPOINT_RESTORE",
		"SYS_RAWIO", "SYS_BOOT", "MKNOD",
	}
	for _, capability := range want {
		fixture := safeInspectFixture()
		fixture.HostConfig.CapAdd = []string{capability}
		if !hasRule(evaluate(fixture), "DS008") {
			t.Errorf("missing dangerous capability %s", capability)
		}
	}
	if len(dangerousCapabilities) != len(want) {
		t.Fatalf("dangerousCapabilities=%v want=%v", dangerousCapabilities, want)
	}
	fixture := safeInspectFixture()
	fixture.HostConfig.CapAdd = []string{"ALL"}
	if !hasRule(evaluate(fixture), "DS008") {
		t.Error("CapAdd=ALL did not trigger DS008")
	}
}

func TestSecurityOptionMatrix(t *testing.T) {
	tests := []struct {
		option    string
		wantDS009 bool
		wantDS013 bool
	}{
		{"seccomp=unconfined", true, true},
		{"seccomp:unconfined", true, true},
		{"apparmor=unconfined", true, true},
		{"apparmor:unconfined", true, true},
		{"label=disable", true, true},
		{"label:disable", true, true},
		{"disable", true, true},
		{"custom-seccomp=unconfined-example", false, true},
		{"no-new-privileges", false, false},
		{"no-new-privileges=true", false, false},
		{"no-new-privileges:true", false, false},
		{"no-new-privileges:false", false, true},
	}
	for _, tt := range tests {
		t.Run(tt.option, func(t *testing.T) {
			fixture := safeInspectFixture()
			fixture.HostConfig.SecurityOpt = []string{tt.option}
			findings := evaluate(fixture)
			if hasRule(findings, "DS009") != tt.wantDS009 || hasRule(findings, "DS013") != tt.wantDS013 {
				t.Fatalf("findings=%#v", findings)
			}
		})
	}
}

func TestNoNewPrivilegesUsesMobyBooleanAndOrderingSemantics(t *testing.T) {
	tests := []struct {
		name    string
		options []string
		want    bool
	}{
		{"bare", []string{"no-new-privileges"}, false},
		{"true", []string{"no-new-privileges=true"}, false},
		{"one", []string{"no-new-privileges=1"}, false},
		{"t", []string{"no-new-privileges=t"}, false},
		{"false", []string{"no-new-privileges=false"}, true},
		{"zero", []string{"no-new-privileges=0"}, true},
		{"true then false", []string{"no-new-privileges=true", "no-new-privileges=false"}, true},
		{"false then true", []string{"no-new-privileges=false", "no-new-privileges=true"}, false},
		{"false then bare", []string{"no-new-privileges=false", "no-new-privileges"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := safeInspectFixture()
			fixture.HostConfig.SecurityOpt = tt.options
			if got := hasRule(evaluate(fixture), "DS013"); got != tt.want {
				t.Fatalf("options=%v finding=%v", tt.options, got)
			}
		})
	}
}

func TestConfiguredRootUserMatrix(t *testing.T) {
	tests := []struct {
		user string
		want bool
	}{
		{"", true}, {" ", true}, {":33", true}, {"root", true}, {"root:group", true}, {"0", true}, {"0:0", true},
		{"000", true}, {"+0", true}, {"+000:1000", true}, {"1000", false},
		{"app", false}, {"ROOT", false}, {"rootless", false}, {"-0", false}, {"+", false}, {"0abc", false},
		{"18446744073709551616", false},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%q", tt.user), func(t *testing.T) {
			fixture := safeInspectFixture()
			fixture.Config.User = tt.user
			if got := hasRule(evaluate(fixture), "DS011"); got != tt.want {
				t.Fatalf("user=%q got=%v", tt.user, got)
			}
		})
	}
}

func TestImageReferenceMatrix(t *testing.T) {
	tests := []struct {
		image string
		want  bool
	}{
		{"alpine", true},
		{"alpine:latest", true},
		{"alpine:LATEST", true},
		{"registry:5000/team/image", true},
		{"registry:5000/team/image:1.2", false},
		{"image@" + validDigest, false},
		{"image:tag@" + validDigest, false},
		{"image@sha256:abc", true},
		{"registry.example/team/UPPER:tag", true},
		{"", true},
	}
	for _, tt := range tests {
		t.Run(strings.ReplaceAll(tt.image, "/", "_"), func(t *testing.T) {
			fixture := safeInspectFixture()
			fixture.Config.Image = tt.image
			if got := hasRule(evaluate(fixture), "DS014"); got != tt.want {
				t.Fatalf("image=%q got=%v findings=%#v", tt.image, got, evaluate(fixture))
			}
		})
	}
}

func TestFindingStringsAreSanitizedAndBounded(t *testing.T) {
	fixture := safeInspectFixture()
	fixture.HostConfig.Privileged = true
	fixture.Name = "/bad\x1b]8;;https://evil.invalid\x07" + strings.Repeat("n", 1000)
	fixture.Config.Image = "bad\n\u202e" + strings.Repeat("i", 1000) + ":1"
	findings := evaluate(fixture)
	if len(findings) == 0 {
		t.Fatal("expected findings")
	}
	for _, finding := range findings {
		if strings.Contains(finding.Container, "\x1b") || strings.Contains(finding.Container, "evil.invalid") ||
			strings.ContainsAny(finding.Image, "\n\r\t") || strings.Contains(finding.Image, "\u202e") {
			t.Fatalf("unsafe finding=%#v", finding)
		}
		if len([]rune(finding.Container)) > 257 || len([]rune(finding.Image)) > 257 {
			t.Fatalf("unbounded finding=%#v", finding)
		}
	}
}

func TestSortFindingsDeterministically(t *testing.T) {
	findings := []Finding{
		{RuleID: "DS014", Severity: SeverityJSON(Low), Container: "z"},
		{RuleID: "DS012", Severity: SeverityJSON(Medium), Container: "beta"},
		{RuleID: "DS013", Severity: SeverityJSON(Medium), Container: "Alpha"},
		{RuleID: "DS011", Severity: SeverityJSON(Medium), Container: "Alpha"},
		{RuleID: "DS001", Severity: SeverityJSON(Critical), Container: "z"},
	}
	SortFindings(findings)
	got := make([]string, 0, len(findings))
	for _, finding := range findings {
		got = append(got, finding.RuleID)
	}
	want := []string{"DS001", "DS011", "DS013", "DS012", "DS014"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("sort=%v want=%v", got, want)
	}
}

func TestAllRulesAreStable(t *testing.T) {
	if len(Rules) != 15 {
		t.Fatalf("got %d rules", len(Rules))
	}
	seen := map[string]bool{}
	for index, rule := range Rules {
		want := fmt.Sprintf("DS%03d", index+1)
		if rule.ID != want {
			t.Errorf("rule %d is %s, want %s", index, rule.ID, want)
		}
		if seen[rule.ID] {
			t.Errorf("duplicate %s", rule.ID)
		}
		seen[rule.ID] = true
		if rule.Summary == "" || rule.Risk == "" || rule.Remediation == "" {
			t.Errorf("incomplete %s", rule.ID)
		}
	}
}

func safeInspectFixture() container.InspectResponse {
	return container.InspectResponse{
		Platform: "linux",
		Name:     "/safe",
		HostConfig: &container.HostConfig{
			ReadonlyRootfs: true,
			SecurityOpt:    []string{"no-new-privileges=true"},
		},
		Config: &container.Config{Image: "registry.example/team/image:1.2", User: "1000"},
	}
}

func bind(source string) func(*container.InspectResponse) {
	return func(value *container.InspectResponse) {
		value.Mounts = []container.MountPoint{{Type: mount.TypeBind, Source: source}}
	}
}

func volume(source string) func(*container.InspectResponse) {
	return func(value *container.InspectResponse) {
		value.Mounts = []container.MountPoint{{Type: mount.TypeVolume, Source: source}}
	}
}

func hasRule(findings []Finding, id string) bool {
	for _, finding := range findings {
		if finding.RuleID == id {
			return true
		}
	}
	return false
}

func evaluate(value container.InspectResponse) []Finding {
	return Evaluate(docker.ProjectContainer(value))
}
