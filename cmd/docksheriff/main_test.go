package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/1184468969/docksheriff/internal/docker"
)

func TestJSONOutputGolden(t *testing.T) {
	engine := &fakeConnection{
		metadata: docker.Metadata{Endpoint: "unix:///var/run/docker.sock"},
		list:     []docker.ContainerSummary{{ID: "abc"}},
		inspects: map[string]docker.Container{
			"abc": inspectResponse("/web\x1b[31m", "alpine:latest", "1000", func(host *docker.ContainerHostConfig) {
				host.ReadonlyRootFilesystem = true
				host.SecurityOptions = []string{"no-new-privileges=true"}
			}),
		},
	}
	var stdout, stderr bytes.Buffer
	code := execute(
		[]string{"--format", "json"},
		&stdout,
		&stderr,
		factory(engine, nil),
		func() time.Time { return time.Date(2026, 8, 13, 6, 30, 0, 0, time.UTC) },
	)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
	want, err := os.ReadFile(filepath.Join("testdata", "scan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if stdout.String() != string(want) {
		t.Fatalf("output mismatch\n--- got ---\n%s--- want ---\n%s", stdout.String(), want)
	}
}

func TestThresholdExitCodes(t *testing.T) {
	for _, severity := range []string{"critical", "high", "medium", "low", "info"} {
		t.Run(severity, func(t *testing.T) {
			engine := criticalEngine()
			code, _, stderr := runWith(t, []string{"--fail-on", severity}, engine, nil, &bytes.Buffer{})
			if code != 1 || stderr != "" {
				t.Fatalf("exit=%d stderr=%q", code, stderr)
			}
		})
	}
	engine := criticalEngine()
	code, _, _ := runWith(t, nil, engine, nil, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("without --fail-on exit=%d", code)
	}
	engine = criticalEngine()
	code, _, _ = runWith(t, []string{"--fail-on", "critical", "--ignore", "DS001"}, engine, nil, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("ignored finding exit=%d", code)
	}
	engine = safeEngine()
	code, _, _ = runWith(t, []string{"--fail-on", "info"}, engine, nil, &bytes.Buffer{})
	if code != 0 {
		t.Fatalf("empty findings exit=%d", code)
	}
}

func TestUsageAndMetadataCommands(t *testing.T) {
	tests := []struct {
		args       []string
		wantCode   int
		wantOutput string
		wantError  string
	}{
		{[]string{"--help"}, 0, "Usage:", ""},
		{[]string{"scan", "--help"}, 0, "Scan is the default command.", ""},
		{[]string{"inspect", "--help"}, 0, "Inspect requires exactly one", ""},
		{[]string{"--version"}, 0, "docksheriff dev", ""},
		{[]string{"rules"}, 0, "DS001 critical", ""},
		{[]string{"explain", "DS002"}, 0, "Why:", ""},
		{[]string{"explain", "NOPE"}, 2, "", "Error: unknown rule"},
		{[]string{"--format", "xml"}, 2, "", "format must be table or json"},
		{[]string{"--fail-on", "urgent"}, 2, "", "invalid fail-on severity"},
		{[]string{"--min-severity", "urgent"}, 2, "", "invalid minimum severity"},
	}
	for _, tt := range tests {
		var stdout, stderr bytes.Buffer
		code := execute(tt.args, &stdout, &stderr, factory(nil, errors.New("must not connect")), time.Now)
		if code != tt.wantCode || !strings.Contains(stdout.String(), tt.wantOutput) || !strings.Contains(stderr.String(), tt.wantError) {
			t.Errorf("args=%q exit=%d stdout=%q stderr=%q", tt.args, code, stdout.String(), stderr.String())
		}
	}
}

func TestConnectionAndEngineErrorsExitTwoWithoutLeaks(t *testing.T) {
	secret := errors.New("tcp://user:password@example.invalid?token=hidden\x1b[31m")
	tests := []struct {
		name    string
		engine  *fakeConnection
		connect error
		args    []string
	}{
		{"connect", nil, errors.New("invalid Docker connection configuration"), nil},
		{"ping", &fakeConnection{pingErr: secret}, nil, nil},
		{"version", &fakeConnection{versionErr: secret}, nil, nil},
		{"list", &fakeConnection{listErr: secret}, nil, nil},
		{"inspect", &fakeConnection{inspectErr: secret}, nil, []string{"inspect", "malicious\x1b[31m"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			code, _, stderr := runWith(t, tt.args, tt.engine, tt.connect, &bytes.Buffer{})
			if code != 2 {
				t.Fatalf("exit=%d stderr=%q", code, stderr)
			}
			for _, unsafe := range []string{"password", "token", "\x1b"} {
				if strings.Contains(stderr, unsafe) {
					t.Fatalf("stderr leaked %q: %q", unsafe, stderr)
				}
			}
		})
	}
}

func TestWriterAndBrokenPipeErrorsExitTwo(t *testing.T) {
	for name, writer := range map[string]*errorWriter{
		"writer":      {err: errors.New("disk full")},
		"broken pipe": {err: syscall.EPIPE},
	} {
		t.Run(name, func(t *testing.T) {
			code, _, stderr := runWith(t, []string{"--format", "json"}, safeEngine(), nil, writer)
			if code != 2 || !strings.Contains(stderr, "output write failed") {
				t.Fatalf("exit=%d stderr=%q", code, stderr)
			}
		})
	}
}

func TestTableOutputHasWhyAndFix(t *testing.T) {
	code, stdout, stderr := runWith(t, nil, criticalEngine(), nil, &bytes.Buffer{})
	if code != 0 || stderr != "" {
		t.Fatalf("exit=%d stderr=%q", code, stderr)
	}
	for _, expected := range []string{"CRITICAL DS001", "Container:", "Image:", "Why:", "Fix:", "Summary:"} {
		if !strings.Contains(stdout, expected) {
			t.Fatalf("output missing %q:\n%s", expected, stdout)
		}
	}
}

func runWith(t *testing.T, args []string, engine *fakeConnection, connectErr error, stdoutWriter interface{ Write([]byte) (int, error) }) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	writer := stdoutWriter
	if _, ok := stdoutWriter.(*bytes.Buffer); ok {
		writer = &stdout
	}
	var stderr bytes.Buffer
	code := execute(args, writer, &stderr, factory(engine, connectErr), func() time.Time {
		return time.Date(2026, 8, 13, 6, 30, 0, 0, time.UTC)
	})
	return code, stdout.String(), stderr.String()
}

func factory(engine *fakeConnection, err error) connectionFactory {
	return func(string) (connection, error) { return engine, err }
}

func criticalEngine() *fakeConnection {
	return &fakeConnection{
		metadata: docker.Metadata{Endpoint: "unix:///var/run/docker.sock"},
		list:     []docker.ContainerSummary{{ID: "critical"}},
		inspects: map[string]docker.Container{
			"critical": inspectResponse("/critical", "demo:1", "1000", func(host *docker.ContainerHostConfig) {
				host.Privileged = true
				host.ReadonlyRootFilesystem = true
				host.SecurityOptions = []string{"no-new-privileges=true"}
			}),
		},
	}
}

func safeEngine() *fakeConnection {
	return &fakeConnection{metadata: docker.Metadata{Endpoint: "unix:///var/run/docker.sock"}}
}

type fakeConnection struct {
	metadata                                 docker.Metadata
	pingErr, versionErr, listErr, inspectErr error
	list                                     []docker.ContainerSummary
	inspects                                 map[string]docker.Container
	closed                                   bool
}

func (f *fakeConnection) Ping(context.Context) (docker.Ping, error) {
	return docker.Ping{}, f.pingErr
}

func (f *fakeConnection) ServerVersion(context.Context) (docker.Version, error) {
	return docker.Version{Version: "28.0.0", APIVersion: "1.48"}, f.versionErr
}

func (f *fakeConnection) ContainerList(context.Context, docker.ListOptions) ([]docker.ContainerSummary, error) {
	return f.list, f.listErr
}

func (f *fakeConnection) ContainerInspect(_ context.Context, id string) (docker.Container, error) {
	if f.inspectErr != nil {
		return docker.Container{}, f.inspectErr
	}
	return f.inspects[id], nil
}

func (f *fakeConnection) Metadata() docker.Metadata { return f.metadata }
func (f *fakeConnection) Close() error {
	f.closed = true
	return nil
}

func inspectResponse(name, image, user string, configure func(*docker.ContainerHostConfig)) docker.Container {
	host := &docker.ContainerHostConfig{}
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

type errorWriter struct{ err error }

func (w *errorWriter) Write([]byte) (int, error) { return 0, w.err }
