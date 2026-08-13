package docker

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/go-connections/sockets"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/client"
	"go.opentelemetry.io/otel/trace/noop"

	"github.com/1184468969/docksheriff/internal/safe"
)

const (
	defaultRequestTimeout  = 10 * time.Second
	maxEngineResponseBytes = 32 << 20
)

// Client is a timeout-enforcing adapter over the official Docker SDK.
type Client struct {
	sdk     *client.Client
	timeout time.Duration
	meta    Metadata
}

// New constructs an official SDK client using Docker environment semantics.
// An explicit host overrides DOCKER_HOST. Insecure TLS is rejected.
func New(host string) (*Client, error) {
	return newClient(host, defaultRequestTimeout)
}

func newClient(host string, timeout time.Duration) (*Client, error) {
	return newClientWithLimit(host, timeout, maxEngineResponseBytes)
}

func newClientWithLimit(host string, timeout time.Duration, responseLimit int64) (*Client, error) {
	configuration, err := resolveConfiguration(host)
	if err != nil {
		return nil, errors.New("invalid Docker connection configuration")
	}
	httpClient, err := directHTTPClient(configuration.host)
	if err != nil {
		return nil, errors.New("invalid Docker connection configuration")
	}

	options := make([]client.Opt, 0, 10)
	if configuration.useFromEnv {
		options = append(options, client.FromEnv)
	} else {
		// Current Docker SDK FromEnv requires a complete mTLS triplet whenever
		// DOCKER_CERT_PATH is set. Optional CA/client material is configured
		// explicitly below while host and API version retain Docker semantics.
		if apiVersion := os.Getenv(client.EnvOverrideAPIVersion); apiVersion != "" {
			options = append(options, client.WithAPIVersion(apiVersion))
		}
	}
	// Reapply the already-validated, credential-free effective host so an
	// explicit --host cannot be affected by a malformed DOCKER_HOST value.
	options = append(options,
		client.WithHost(configuration.host),
		client.WithHTTPClient(httpClient),
	)
	if configuration.tls.enabled {
		options = append(options, client.WithTLSClientConfig(
			configuration.tls.ca,
			configuration.tls.cert,
			configuration.tls.key,
		))
	}
	options = append(options,
		client.WithAPIVersionNegotiation(),
		client.WithTimeout(timeout),
		client.WithTraceProvider(noop.NewTracerProvider()),
		client.WithResponseHook(func(response *http.Response) {
			if response.Body != nil {
				response.Body = http.MaxBytesReader(nil, response.Body, responseLimit)
			}
		}),
	)

	//nolint:govet // The release contract explicitly requires NewClientWithOpts.
	sdk, err := client.NewClientWithOpts(options...)
	if err != nil {
		return nil, errors.New("invalid Docker connection configuration")
	}
	return &Client{sdk: sdk, timeout: timeout, meta: configuration.metadata}, nil
}

// Close releases idle SDK transport resources.
func (c *Client) Close() error { return c.sdk.Close() }

// Metadata returns the already-redacted effective connection description.
func (c *Client) Metadata() Metadata { return c.meta }

func (c *Client) Ping(ctx context.Context) (Ping, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	result, err := c.sdk.Ping(callCtx, client.PingOptions{NegotiateAPIVersion: true})
	_ = result
	return Ping{}, publicCallError("ping", err)
}

func (c *Client) ServerVersion(ctx context.Context) (Version, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	result, err := c.sdk.ServerVersion(callCtx, client.ServerVersionOptions{})
	return Version{Version: result.Version, APIVersion: result.APIVersion}, publicCallError("server version", err)
}

func (c *Client) ContainerList(ctx context.Context, options ListOptions) ([]ContainerSummary, error) {
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	result, err := c.sdk.ContainerList(callCtx, client.ContainerListOptions{All: options.All})
	items := make([]ContainerSummary, len(result.Items))
	for index, item := range result.Items {
		items[index] = ContainerSummary{ID: item.ID}
	}
	return items, publicCallError("container list", err)
}

func (c *Client) ContainerInspect(ctx context.Context, id string) (Container, error) {
	id, err := normalizeContainerTarget(id)
	if err != nil {
		return Container{}, publicCallError("container inspect", err)
	}
	callCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	result, err := c.sdk.ContainerInspect(callCtx, id, client.ContainerInspectOptions{})
	if err != nil {
		return Container{}, publicCallError("container inspect", err)
	}
	return ProjectContainer(result.Container), nil
}

// ProjectContainer immediately narrows the SDK's broad Inspect response to the
// fields required by DS001-DS014. Sensitive unrelated fields cannot cross the
// Engine interface after this projection.
func ProjectContainer(inspect container.InspectResponse) Container {
	projected := Container{Platform: inspect.Platform, Name: inspect.Name}
	if inspect.Config != nil {
		projected.Config = &ContainerConfig{Image: inspect.Config.Image, User: inspect.Config.User}
	}
	if inspect.HostConfig != nil {
		host := inspect.HostConfig
		projected.HostConfig = &ContainerHostConfig{
			Privileged:             host.Privileged,
			NetworkMode:            string(host.NetworkMode),
			PIDMode:                string(host.PidMode),
			IPCMode:                string(host.IpcMode),
			UTSMode:                string(host.UTSMode),
			CgroupNamespaceMode:    string(host.CgroupnsMode),
			CapabilitiesAdded:      append([]string(nil), host.CapAdd...),
			SecurityOptions:        append([]string(nil), host.SecurityOpt...),
			HasDeviceAccess:        len(host.Devices) > 0 || len(host.DeviceCgroupRules) > 0 || len(host.DeviceRequests) > 0,
			ReadonlyRootFilesystem: host.ReadonlyRootfs,
		}
		for _, item := range host.Mounts {
			if item.Type == mount.TypeBind {
				projected.BindMountSources = append(projected.BindMountSources, item.Source)
			}
		}
	}
	for _, item := range inspect.Mounts {
		if item.Type == mount.TypeBind {
			projected.BindMountSources = append(projected.BindMountSources, item.Source)
		}
	}
	return projected
}

type callError struct {
	operation string
	cause     error
}

func (e *callError) Error() string { return "Docker " + e.operation + " failed" }
func (e *callError) Unwrap() error { return e.cause }

func publicCallError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return &callError{operation: operation, cause: err}
}

type tlsFiles struct {
	enabled       bool
	ca, cert, key string
}

type resolvedConfiguration struct {
	metadata   Metadata
	tls        tlsFiles
	host       string
	useFromEnv bool
}

func resolveConfiguration(override string) (resolvedConfiguration, error) {
	host := override
	if host == "" {
		host = os.Getenv(client.EnvOverrideHost)
	}
	if host == "" {
		host = client.DefaultDockerHost
	}
	parsed, err := parseEndpoint(host)
	if err != nil {
		return resolvedConfiguration{}, err
	}

	tlsVerify := os.Getenv(client.EnvTLSVerify) != ""
	certPath := os.Getenv(client.EnvOverrideCertPath)
	if certPath != "" && !tlsVerify {
		return resolvedConfiguration{}, errors.New("DOCKER_CERT_PATH requires verified TLS")
	}
	tlsEnabled := parsed.Scheme == "https" || tlsVerify
	files := tlsFiles{enabled: tlsEnabled}
	if certPath != "" {
		info, statErr := os.Stat(certPath)
		if statErr != nil || !info.IsDir() {
			return resolvedConfiguration{}, errors.New("invalid Docker TLS material")
		}
		files.ca, err = optionalRegularFile(filepath.Join(certPath, "ca.pem"))
		if err != nil {
			return resolvedConfiguration{}, err
		}
		files.cert, err = optionalRegularFile(filepath.Join(certPath, "cert.pem"))
		if err != nil {
			return resolvedConfiguration{}, err
		}
		files.key, err = optionalRegularFile(filepath.Join(certPath, "key.pem"))
		if err != nil {
			return resolvedConfiguration{}, err
		}
		if (files.cert == "") != (files.key == "") {
			return resolvedConfiguration{}, errors.New("docker client certificate and key must be configured together")
		}
		if files.ca == "" && files.cert == "" {
			return resolvedConfiguration{}, errors.New("docker TLS material is missing")
		}
	}
	if tlsEnabled && (parsed.Scheme == "unix" || parsed.Scheme == "npipe") {
		return resolvedConfiguration{}, errors.New("TLS cannot be used with a local socket")
	}

	return resolvedConfiguration{
		metadata: Metadata{
			Endpoint:    redactEndpoint(parsed),
			InsecureTCP: isTCPEndpoint(parsed.Scheme) && !tlsEnabled,
		},
		tls:        files,
		host:       connectionEndpoint(parsed),
		useFromEnv: certPath == "" && override == "",
	}, nil
}

func directHTTPClient(endpoint string) (*http.Client, error) {
	hostURL, err := client.ParseHostURL(endpoint)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{}
	if err = sockets.ConfigureTransport(transport, hostURL.Scheme, hostURL.Host); err != nil {
		return nil, err
	}
	// Docker Engine traffic must go directly to the configured endpoint; SDK
	// proxy environment handling would otherwise widen the network boundary.
	transport.Proxy = nil
	return &http.Client{Transport: transport, CheckRedirect: client.CheckRedirect}, nil
}

func optionalRegularFile(path string) (string, error) {
	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("invalid Docker TLS material")
	}
	return path, nil
}

func parseEndpoint(host string) (*url.URL, error) {
	if len(host) > 4096 {
		return nil, errors.New("docker endpoint is too long")
	}
	parsed, err := url.Parse(host)
	if err != nil || parsed.Scheme == "" {
		return nil, errors.New("invalid Docker endpoint")
	}
	parsed.Scheme = strings.ToLower(parsed.Scheme)
	switch parsed.Scheme {
	case "unix", "npipe":
		if parsed.Path == "" && parsed.Host == "" {
			return nil, errors.New("empty local Docker endpoint")
		}
	case "tcp", "http", "https":
		if parsed.Host == "" {
			return nil, errors.New("empty Docker TCP endpoint")
		}
	default:
		return nil, fmt.Errorf("unsupported Docker endpoint scheme")
	}
	return parsed, nil
}

func isTCPEndpoint(scheme string) bool {
	return scheme == "tcp" || scheme == "http" || scheme == "https"
}

func redactEndpoint(parsed *url.URL) string {
	return safe.Text(connectionEndpoint(parsed))
}

func connectionEndpoint(parsed *url.URL) string {
	clean := *parsed
	clean.User = nil
	clean.RawQuery = ""
	clean.ForceQuery = false
	clean.Fragment = ""
	return clean.String()
}

func normalizeContainerTarget(value string) (string, error) {
	value = strings.TrimPrefix(value, "/")
	if value == "" || len(value) > 4096 {
		return "", errors.New("invalid container name or ID")
	}
	for index, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			continue
		}
		if index > 0 && (r == '_' || r == '.' || r == '-') {
			continue
		}
		return "", errors.New("invalid container name or ID")
	}
	return value, nil
}

// RedactEndpoint returns a display-safe endpoint without userinfo, query, or
// fragment data. Invalid values are replaced rather than echoed.
func RedactEndpoint(value string) string {
	if strings.TrimSpace(value) == "" {
		return ""
	}
	parsed, err := parseEndpoint(value)
	if err != nil {
		return "redacted"
	}
	return redactEndpoint(parsed)
}

var _ Engine = (*Client)(nil)
