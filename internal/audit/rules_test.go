package audit

import (
	"fmt"
	"github.com/1184468969/docksheriff/internal/dockerapi"
	"testing"
)

func TestCriticalRules(t *testing.T) {
	c := &dockerapi.ContainerConfig{Image: "demo:1", User: "1000"}
	h := &dockerapi.HostConfig{Privileged: true, ReadonlyRootfs: true, SecurityOpt: []string{"no-new-privileges"}, Binds: []string{"/var/run/docker.sock:/sock", "/:/host", "/var/lib/docker:/data"}}
	got := Evaluate("bad\x1b[31mname", "demo:1", c, h)
	want := map[string]bool{"DS001": true, "DS002": true, "DS003": true, "DS004": true}
	for _, f := range got {
		delete(want, f.ID)
		if f.Container != "badname" {
			t.Fatalf("unsanitized name: %q", f.Container)
		}
	}
	if len(want) > 0 {
		t.Fatalf("missing: %v", want)
	}
}
func TestSensitiveBoundary(t *testing.T) {
	c := &dockerapi.ContainerConfig{Image: "x@sha256:abc", User: "1"}
	base := dockerapi.HostConfig{ReadonlyRootfs: true, SecurityOpt: []string{"no-new-privileges"}}
	base.Binds = []string{"/etcetera:/x"}
	if got := Evaluate("x", c.Image, c, &base); len(got) != 0 {
		t.Fatalf("false positive: %#v", got)
	}
	base.Binds = []string{"/etc/passwd:/x"}
	if got := Evaluate("x", c.Image, c, &base); len(got) != 1 || got[0].ID != "DS005" {
		t.Fatalf("got %#v", got)
	}
}
func TestDefaults(t *testing.T) {
	got := Evaluate("x", "alpine", &dockerapi.ContainerConfig{}, &dockerapi.HostConfig{})
	want := map[string]bool{"DS011": true, "DS012": true, "DS013": true, "DS014": true}
	for _, f := range got {
		delete(want, f.ID)
	}
	if len(want) > 0 {
		t.Fatal(want)
	}
}

func TestAllRulesAreStable(t *testing.T) {
	if len(Rules) != 15 {
		t.Fatalf("got %d rules", len(Rules))
	}
	seen := map[string]bool{}
	for i, r := range Rules {
		want := fmt.Sprintf("DS%03d", i+1)
		if r.ID != want {
			t.Errorf("rule %d is %s, want %s", i, r.ID, want)
		}
		if seen[r.ID] {
			t.Errorf("duplicate %s", r.ID)
		}
		seen[r.ID] = true
		if r.Summary == "" || r.Risk == "" || r.Remediation == "" {
			t.Errorf("incomplete %s", r.ID)
		}
	}
}

func TestNamedVolumeDoesNotLookLikeRuntimeBind(t *testing.T) {
	c := &dockerapi.ContainerConfig{Image: "alpine:3", User: "1000"}
	h := &dockerapi.HostConfig{ReadonlyRootfs: true, SecurityOpt: []string{"no-new-privileges"}, Mounts: []dockerapi.Mount{{Type: "volume", Source: "/var/lib/docker/volumes/demo/_data"}}}
	if got := Evaluate("demo", c.Image, c, h); len(got) != 0 {
		t.Fatalf("named volume produced findings: %#v", got)
	}
}

func TestSanitizeTerminalControls(t *testing.T) {
	got := Sanitize("safe\n\x1b[31mred\x1b[0m\u202eevil")
	if got != "saferedevil" {
		t.Fatalf("Sanitize()=%q", got)
	}
}
