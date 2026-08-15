package app

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/1184468969/docksheriff/internal/audit"
	"github.com/1184468969/docksheriff/internal/docker"
)

func TestScanEmptyAndMultipleContainers(t *testing.T) {
	fixed := func() time.Time { return time.Date(2026, 8, 13, 6, 0, 0, 0, time.UTC) }
	tests := []struct {
		name        string
		engine      *fakeEngine
		metadata    docker.Metadata
		wantScans   int
		wantRules   []string
		wantSummary int
	}{
		{
			name:      "empty daemon",
			engine:    &fakeEngine{},
			metadata:  docker.Metadata{Endpoint: "unix:///var/run/docker.sock"},
			wantRules: []string{},
		},
		{
			name: "multiple containers deterministic order",
			engine: &fakeEngine{
				list: []docker.ContainerSummary{{ID: "b"}, {ID: "a"}},
				inspects: map[string]docker.Container{
					"b": inspectFixture("/Zulu", "alpine", "1000", func(host *docker.ContainerHostConfig) { host.Privileged = true }),
					"a": inspectFixture("/alpha", "alpine:3", "root", nil),
				},
			},
			metadata:    docker.Metadata{Endpoint: "tcp://safe.example:2375", InsecureTCP: true},
			wantScans:   2,
			wantRules:   []string{"DS015", "DS001", "DS011", "DS014"},
			wantSummary: 4,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			report, err := Scan(context.Background(), tt.engine, tt.metadata, Options{}, fixed)
			if err != nil {
				t.Fatal(err)
			}
			if report.GeneratedAt != "2026-08-13T06:00:00Z" || report.ScannedContainers != tt.wantScans || report.Summary.Total != tt.wantSummary {
				t.Fatalf("report=%#v", report)
			}
			gotRules := make([]string, 0, len(report.Findings))
			for _, finding := range report.Findings {
				gotRules = append(gotRules, finding.RuleID)
			}
			if !reflect.DeepEqual(gotRules, tt.wantRules) {
				t.Fatalf("rules=%v want=%v", gotRules, tt.wantRules)
			}
		})
	}
}

func TestScanFailuresAreStableAndPreserveCancellation(t *testing.T) {
	secret := errors.New("tcp://user:password@example.invalid?token=hidden\x1b[31m")
	tests := []struct {
		name, want string
		engine     *fakeEngine
		options    Options
	}{
		{"ping", "Docker ping failed", &fakeEngine{pingErr: secret}, Options{}},
		{"version", "Docker server version failed", &fakeEngine{versionErr: secret}, Options{}},
		{"list", "Docker container list failed", &fakeEngine{listErr: secret}, Options{}},
		{"inspect", "Docker container inspect failed", &fakeEngine{inspectErr: secret}, Options{InspectTarget: "malicious\x1b[31m"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Scan(context.Background(), tt.engine, docker.Metadata{}, tt.options, time.Now)
			if err == nil || err.Error() != tt.want || !errors.Is(err, secret) {
				t.Fatalf("error=%v", err)
			}
			if strings.Contains(err.Error(), "password") || strings.Contains(err.Error(), "\x1b") {
				t.Fatalf("unsafe error=%v", err)
			}
		})
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Scan(canceled, &fakeEngine{pingErr: context.Canceled}, docker.Metadata{}, Options{}, time.Now)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation not preserved: %v", err)
	}
}

func TestScanIgnoreInspectAndThreshold(t *testing.T) {
	engine := &fakeEngine{inspects: map[string]docker.Container{
		"target": inspectFixture("/demo", "alpine", "", nil),
	}}
	report, err := Scan(context.Background(), engine, docker.Metadata{InsecureTCP: true}, Options{
		InspectTarget: "target",
		IgnoredRules:  map[string]struct{}{"DS011": {}, "DS012": {}, "DS013": {}, "DS014": {}, "DS015": {}},
	}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Total != 0 || len(report.Findings) != 0 || engine.listCalls != 0 || engine.inspectCalls != 1 {
		t.Fatalf("report=%#v engine=%#v", report, engine)
	}
	if ThresholdReached(report, audit.Info, true) || ThresholdReached(report, audit.Critical, false) {
		t.Fatal("empty report reached threshold")
	}

	report.Findings = []audit.Finding{{RuleID: "DS012", Severity: audit.SeverityJSON(audit.Medium)}}
	if !ThresholdReached(report, audit.Medium, true) || ThresholdReached(report, audit.High, true) {
		t.Fatal("threshold comparison is incorrect")
	}
}

func TestScanRedactsMaliciousMetadataAndSanitizesVersion(t *testing.T) {
	report, err := Scan(context.Background(), &fakeEngine{}, docker.Metadata{
		Endpoint: "tcp://user:password@example.invalid:2375?token=hidden#fragment",
	}, Options{}, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if report.Docker.Endpoint != "tcp://example.invalid:2375" {
		t.Fatalf("endpoint=%q", report.Docker.Endpoint)
	}
	for _, secret := range []string{"user", "password", "token", "fragment"} {
		if strings.Contains(report.Docker.Endpoint, secret) {
			t.Fatalf("endpoint leaked %q: %q", secret, report.Docker.Endpoint)
		}
	}
}

func TestScanRejectsNonLinuxOrMissingPlatform(t *testing.T) {
	for _, platform := range []string{"", "windows"} {
		t.Run(platform, func(t *testing.T) {
			engine := &fakeEngine{inspects: map[string]docker.Container{
				"target": inspectFixture("/demo", "image:1", "1000", nil),
			}}
			engine.inspects["target"] = func(value docker.Container) docker.Container {
				value.Platform = platform
				return value
			}(engine.inspects["target"])
			_, err := Scan(context.Background(), engine, docker.Metadata{}, Options{InspectTarget: "target"}, time.Now)
			if err == nil || err.Error() != "docker container platform is unsupported" {
				t.Fatalf("platform=%q error=%v", platform, err)
			}
		})
	}
}

type fakeEngine struct {
	pingErr, versionErr, listErr, inspectErr error
	list                                     []docker.ContainerSummary
	inspects                                 map[string]docker.Container
	listCalls, inspectCalls                  int
}

func (f *fakeEngine) Ping(context.Context) (docker.Ping, error) {
	return docker.Ping{}, f.pingErr
}

func (f *fakeEngine) ServerVersion(context.Context) (docker.Version, error) {
	return docker.Version{Version: "28.0.0", APIVersion: "1.48"}, f.versionErr
}

func (f *fakeEngine) ContainerList(context.Context, docker.ListOptions) ([]docker.ContainerSummary, error) {
	f.listCalls++
	return f.list, f.listErr
}

func (f *fakeEngine) ContainerInspect(_ context.Context, id string) (docker.Container, error) {
	f.inspectCalls++
	if f.inspectErr != nil {
		return docker.Container{}, f.inspectErr
	}
	return f.inspects[id], nil
}

func inspectFixture(name, image, user string, configure func(*docker.ContainerHostConfig)) docker.Container {
	host := &docker.ContainerHostConfig{ReadonlyRootFilesystem: true, SecurityOptions: []string{"no-new-privileges=true"}}
	if configure != nil {
		configure(host)
	}
	return docker.Container{
		Platform:   "linux",
		Name:       name,
		HostConfig: host,
		Config:     &docker.ContainerConfig{Image: image, User: user},
	}
}

var _ docker.Engine = (*fakeEngine)(nil)
