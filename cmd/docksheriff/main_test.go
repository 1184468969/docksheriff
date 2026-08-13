package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestJSONOutputGolden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_ping":
			_, _ = w.Write([]byte("OK"))
		case "/version":
			_, _ = w.Write([]byte(`{"ApiVersion":"1.44","MinAPIVersion":"1.24"}`))
		case "/v1.44/containers/json":
			_, _ = w.Write([]byte(`[{"Id":"abc"}]`))
		case "/v1.44/containers/abc/json":
			_, _ = w.Write([]byte(`{"Name":"/web\u001b[31m","Config":{"Image":"alpine:latest","User":"1000"},"HostConfig":{"ReadonlyRootfs":true,"SecurityOpt":["no-new-privileges"]}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	out, code := captureStdout(t, func() int { return run([]string{"--host", srv.URL, "--format", "json"}) })
	if code != 0 {
		t.Fatalf("exit code %d", code)
	}
	want, err := os.ReadFile(filepath.Join("testdata", "scan.json"))
	if err != nil {
		t.Fatal(err)
	}
	if out != string(want) {
		t.Fatalf("output mismatch\n--- got ---\n%s--- want ---\n%s", out, want)
	}
}

func TestUsageExitCodes(t *testing.T) {
	if _, code := captureStdout(t, func() int { return run([]string{"explain", "NOPE"}) }); code != 2 {
		t.Fatalf("unknown rule exit=%d", code)
	}
	if _, code := captureStdout(t, func() int { return run([]string{"rules"}) }); code != 0 {
		t.Fatalf("rules exit=%d", code)
	}
}

func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	code := fn()
	_ = w.Close()
	os.Stdout = old
	b, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}
	return string(b), code
}
