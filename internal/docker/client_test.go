package docker

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
)

func TestEngineInterfaceIsMinimalAndReadOnly(t *testing.T) {
	typeOfEngine := reflect.TypeOf((*Engine)(nil)).Elem()
	want := []string{"ContainerInspect", "ContainerList", "Ping", "ServerVersion"}
	if typeOfEngine.NumMethod() != len(want) {
		t.Fatalf("Engine has %d methods, want %d", typeOfEngine.NumMethod(), len(want))
	}
	for index, name := range want {
		if typeOfEngine.Method(index).Name != name {
			t.Fatalf("Engine method %d = %s, want %s", index, typeOfEngine.Method(index).Name, name)
		}
	}
	for _, forbidden := range []string{"Create", "Start", "Stop", "Restart", "Kill", "Remove", "Update", "Exec", "Copy", "Pull", "Push", "Build", "Prune"} {
		if _, found := typeOfEngine.MethodByName(forbidden); found {
			t.Fatalf("forbidden Engine method %s", forbidden)
		}
	}
}

func TestOfficialClientReadOnlyRequestsAndNegotiation(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.RequestURI())
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			t.Errorf("unexpected method %s", r.Method)
		}
		switch r.URL.Path {
		case "/_ping":
			w.Header().Set("API-Version", "1.48")
			_, _ = w.Write([]byte("OK"))
		case "/version", "/v1.48/version":
			_, _ = w.Write([]byte(`{"Version":"28.0.0","ApiVersion":"1.48","MinAPIVersion":"1.24"}`))
		case "/v1.48/containers/json":
			_, _ = w.Write([]byte(`[{"Id":"abc","Labels":{"secret":"hidden"},"HostConfig":{"Annotations":{"secret":"hidden"}}}]`))
		case "/v1.48/containers/abc/json":
			_, _ = w.Write([]byte(`{"Id":"abc","Platform":"linux","Name":"/demo","Config":{"Image":"alpine:3","User":"1000","Env":["TOKEN=hidden"],"Labels":{"secret":"hidden"}},"HostConfig":{"Annotations":{"secret":"hidden"}}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := newClient(server.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	ctx := context.Background()
	if _, err = client.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	version, err := client.ServerVersion(ctx)
	if err != nil || version.APIVersion != "1.48" {
		t.Fatalf("version=%#v err=%v", version, err)
	}
	items, err := client.ContainerList(ctx, ListOptions{})
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%#v err=%v", items, err)
	}
	if got, want := reflect.TypeOf(items[0]).NumField(), 1; got != want {
		t.Fatalf("container-list projection has %d fields, want %d: %#v", got, want, items[0])
	}
	inspect, err := client.ContainerInspect(ctx, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if inspect.Platform != "linux" {
		t.Fatalf("projected platform=%q", inspect.Platform)
	}
	if _, found := reflect.TypeOf(*inspect.Config).FieldByName("Env"); found {
		t.Fatal("container projection exposes environment values")
	}
	if _, found := reflect.TypeOf(*inspect.Config).FieldByName("Labels"); found {
		t.Fatal("container projection exposes arbitrary labels")
	}
	if _, found := reflect.TypeOf(*inspect.HostConfig).FieldByName("Annotations"); found {
		t.Fatal("container projection exposes arbitrary annotations")
	}
	joined := strings.Join(requests, "\n")
	if !strings.Contains(joined, "GET /v1.48/containers/json") || !strings.Contains(joined, "GET /v1.48/containers/abc/json") {
		t.Fatalf("requests did not negotiate API 1.48:\n%s", joined)
	}
}

func TestContainerInspectTargetCannotChangeRequestPath(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests++
	}))
	defer server.Close()
	client, err := newClient(server.URL, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	for _, target := range []string{"../version", "abc/json?size=1", "abc#fragment", "abc/def", " name", "", strings.Repeat("a", 4097)} {
		_, err = client.ContainerInspect(context.Background(), target)
		if err == nil || err.Error() != "Docker container inspect failed" {
			t.Errorf("target %q error=%v", target, err)
		}
	}
	if requests != 0 {
		t.Fatalf("invalid Inspect targets caused %d Engine request(s)", requests)
	}

	for _, target := range []string{"abc", "/abc", "name_1.2-test"} {
		got, normalizeErr := normalizeContainerTarget(target)
		if normalizeErr != nil || got == "" {
			t.Errorf("valid target %q normalized to %q, error=%v", target, got, normalizeErr)
		}
	}
}

func TestProjectContainerIncludesAllDeviceAccessForms(t *testing.T) {
	for name, configure := range map[string]func(*container.HostConfig){
		"mapping": func(host *container.HostConfig) {
			host.Devices = []container.DeviceMapping{{PathOnHost: "/dev/kvm"}}
		},
		"cgroup rule": func(host *container.HostConfig) {
			host.DeviceCgroupRules = []string{"c 10:232 rwm"}
		},
		"request": func(host *container.HostConfig) {
			host.DeviceRequests = []container.DeviceRequest{{Driver: "cdi"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			host := &container.HostConfig{}
			configure(host)
			projected := ProjectContainer(container.InspectResponse{Platform: "linux", HostConfig: host})
			if projected.HostConfig == nil || !projected.HostConfig.HasDeviceAccess {
				t.Fatalf("projected=%#v", projected)
			}
		})
	}
}

func TestEngineTransportIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:8181")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:8181")
	t.Setenv("NO_PROXY", "")

	httpClient, err := directHTTPClient("tcp://engine.invalid:2375")
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := httpClient.Transport.(*http.Transport)
	if !ok || transport.Proxy != nil {
		t.Fatal("Engine transport retained an HTTP proxy function")
	}
	var dialedAddress string
	transport.DialContext = func(_ context.Context, _, address string) (net.Conn, error) {
		dialedAddress = address
		return nil, errors.New("test dial stopped")
	}
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://engine.invalid:2375/_ping", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = httpClient.Do(request)
	if dialedAddress != "engine.invalid:2375" {
		t.Fatalf("Engine transport dialed %q instead of configured endpoint", dialedAddress)
	}
}

func TestEngineResponsesAreSizeLimited(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/_ping":
			w.Header().Set("API-Version", "1.48")
			_, _ = w.Write([]byte("OK"))
		case "/v1.48/version":
			_, _ = w.Write([]byte(`{"Version":"` + strings.Repeat("x", 1024) + `"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client, err := newClientWithLimit(server.URL, time.Second, 128)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if _, err = client.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err = client.ServerVersion(context.Background())
	var limitError *http.MaxBytesError
	if err == nil || !errors.As(err, &limitError) || limitError.Limit != 128 {
		t.Fatalf("oversized response error=%v", err)
	}
	if err.Error() != "Docker server version failed" {
		t.Fatalf("public error exposed response detail: %v", err)
	}
}

func TestEachClientCallHasIndependentTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	client, err := newClient(server.URL, 20*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	for _, call := range []func() error{
		func() error { _, err := client.Ping(context.Background()); return err },
		func() error { _, err := client.ServerVersion(context.Background()); return err },
		func() error {
			_, err := client.ContainerList(context.Background(), ListOptions{})
			return err
		},
		func() error { _, err := client.ContainerInspect(context.Background(), "demo"); return err },
	} {
		started := time.Now()
		err := call()
		if err == nil || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("call error=%v", err)
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("call timeout took %s", elapsed)
		}
		if strings.Contains(err.Error(), server.URL) {
			t.Fatalf("public error leaked endpoint: %v", err)
		}
	}
}

func TestEndpointPrecedenceRedactionAndDS015(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://env:secret@env.example:2375?token=hidden")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	t.Setenv("DOCKER_CERT_PATH", "")

	config, err := resolveConfiguration("")
	if err != nil {
		t.Fatal(err)
	}
	if config.metadata.Endpoint != "tcp://env.example:2375" || !config.metadata.InsecureTCP {
		t.Fatalf("environment metadata=%#v", config.metadata)
	}
	config, err = resolveConfiguration("tcp://flag:password@flag.example:2376?auth=hidden")
	if err != nil {
		t.Fatal(err)
	}
	if config.metadata.Endpoint != "tcp://flag.example:2376" || !config.metadata.InsecureTCP {
		t.Fatalf("override metadata=%#v", config.metadata)
	}
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	config, err = resolveConfiguration("tcp://flag.example:2375")
	if err != nil || config.metadata.InsecureTCP || !config.tls.enabled {
		t.Fatalf("TLS metadata=%#v err=%v", config, err)
	}
	config, err = resolveConfiguration("https://flag.example:2376")
	if err != nil || config.metadata.InsecureTCP || !config.tls.enabled {
		t.Fatalf("HTTPS metadata=%#v err=%v", config, err)
	}
	t.Setenv("DOCKER_TLS_VERIFY", "")
	config, err = resolveConfiguration("unix:///var/run/docker.sock")
	if err != nil || config.metadata.InsecureTCP {
		t.Fatalf("Unix metadata=%#v err=%v", config, err)
	}
}

func TestRedactEndpointRejectsInvalidInput(t *testing.T) {
	if got := RedactEndpoint("not an endpoint user:password?token=hidden"); got != "redacted" {
		t.Fatalf("RedactEndpoint()=%q", got)
	}
	if got := RedactEndpoint("tcp://user:password@example.invalid:2375?token=hidden#fragment"); got != "tcp://example.invalid:2375" {
		t.Fatalf("RedactEndpoint()=%q", got)
	}
}

func TestTLSMaterialModesAndNoInsecureSkipVerify(t *testing.T) {
	directory := t.TempDir()
	t.Setenv("DOCKER_HOST", "tcp://docker.example:2376")
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	t.Setenv("DOCKER_CERT_PATH", "")

	config, err := resolveConfiguration("")
	if err != nil || !config.tls.enabled || config.tls.ca != "" || config.tls.cert != "" {
		t.Fatalf("system CA config=%#v err=%v", config, err)
	}
	t.Setenv("DOCKER_CERT_PATH", directory)
	writeTestCertificate(t, filepath.Join(directory, "ca.pem"), filepath.Join(directory, "unused.key"))
	config, err = resolveConfiguration("")
	if err != nil || config.tls.ca == "" || config.tls.cert != "" {
		t.Fatalf("CA-only config=%#v err=%v", config, err)
	}
	writeTestCertificate(t, filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem"))
	config, err = resolveConfiguration("")
	if err != nil || config.tls.ca == "" || config.tls.cert == "" || config.tls.key == "" {
		t.Fatalf("mTLS config=%#v err=%v", config, err)
	}
	client, err := newClient("", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()

	t.Setenv("DOCKER_TLS_VERIFY", "")
	if _, err := resolveConfiguration(""); err == nil {
		t.Fatal("DOCKER_CERT_PATH without verification was accepted")
	}
}

func TestMissingTLSMaterialIsRejected(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://docker.example:2376")
	t.Setenv("DOCKER_TLS_VERIFY", "1")
	t.Setenv("DOCKER_CERT_PATH", filepath.Join(t.TempDir(), "missing"))
	if _, err := resolveConfiguration(""); err == nil {
		t.Fatal("missing TLS directory was accepted")
	}
	t.Setenv("DOCKER_CERT_PATH", t.TempDir())
	if _, err := resolveConfiguration(""); err == nil {
		t.Fatal("empty TLS directory was accepted")
	}
}

func TestClientConfigurationErrorsDoNotLeakSensitiveValues(t *testing.T) {
	t.Setenv("DOCKER_CERT_PATH", "/private/secret/certificates")
	t.Setenv("DOCKER_TLS_VERIFY", "")
	client, err := New("tcp://user:password@example.invalid:2376?token=hidden\x1b[31m")
	if client != nil || err == nil {
		t.Fatalf("client=%v err=%v", client, err)
	}
	for _, secret := range []string{"password", "token", "/private/secret", "\x1b"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("configuration error leaked %q: %v", secret, err)
		}
	}
}

func writeTestCertificate(t *testing.T, certificatePath, keyPath string) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "DockSheriff test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	key := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
	if err := os.WriteFile(certificatePath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
}
