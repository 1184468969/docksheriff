// Package engine contains the complete, deliberately small, read-only Docker API surface.
package engine

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/1184468969/docksheriff/internal/dockerapi"
)

const (
	requestTimeout = 10 * time.Second
	maxAPIVersion  = "1.48" // Docker Engine 27; older daemons are negotiated down.
)

type Client struct {
	http                    *http.Client
	base, version, endpoint string
	insecureTCP             bool
}

func New(host string) (*Client, error) {
	if host == "" {
		host = os.Getenv("DOCKER_HOST")
	}
	if host == "" {
		host = "unix:///var/run/docker.sock"
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("parse Docker endpoint: %w", err)
	}
	transport := &http.Transport{}
	base := "http://docker"
	insecure := false
	switch u.Scheme {
	case "unix":
		if u.Path == "" {
			return nil, fmt.Errorf("Docker Unix endpoint has no socket path")
		}
		path := u.Path
		transport.DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: requestTimeout}).DialContext(ctx, "unix", path)
		}
	case "tcp", "http", "https":
		if u.Host == "" {
			return nil, fmt.Errorf("Docker TCP endpoint has no host")
		}
		useTLS := u.Scheme == "https" || (u.Scheme == "tcp" && os.Getenv("DOCKER_TLS_VERIFY") != "")
		insecure = !useTLS
		scheme := "http"
		if useTLS {
			scheme = "https"
		}
		base = scheme + "://" + u.Host
		if scheme == "https" {
			tlsConfig, err := dockerTLSConfig(u.Hostname())
			if err != nil {
				return nil, err
			}
			transport.TLSClientConfig = tlsConfig
		}
	default:
		return nil, fmt.Errorf("unsupported Docker endpoint scheme %q", u.Scheme)
	}
	return &Client{http: &http.Client{Transport: transport}, base: base, endpoint: redactEndpoint(u), insecureTCP: insecure}, nil
}

func dockerTLSConfig(serverName string) (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	dir := os.Getenv("DOCKER_CERT_PATH")
	if dir == "" {
		return config, nil
	}
	ca, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, fmt.Errorf("load Docker CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("load Docker CA: invalid PEM")
	}
	config.RootCAs = pool
	cert, err := tls.LoadX509KeyPair(filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem"))
	if err != nil {
		return nil, fmt.Errorf("load Docker client certificate: %w", err)
	}
	config.Certificates = []tls.Certificate{cert}
	return config, nil
}

func redactEndpoint(u *url.URL) string {
	clean := *u
	clean.User = nil
	clean.RawQuery = ""
	clean.Fragment = ""
	return clean.String()
}
func (c *Client) Endpoint() string  { return c.endpoint }
func (c *Client) InsecureTCP() bool { return c.insecureTCP }
func (c *Client) Close() error      { c.http.CloseIdleConnections(); return nil }

func (c *Client) get(ctx context.Context, path string, out any) error {
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return fmt.Errorf("create Docker request: %w", err)
	}
	res, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("Docker request to %s failed: %w", c.endpoint, err)
	}
	defer res.Body.Close()
	if res.StatusCode/100 != 2 {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 4096))
		return fmt.Errorf("Docker API at %s returned %s", c.endpoint, res.Status)
	}
	if out != nil {
		if err := json.NewDecoder(io.LimitReader(res.Body, 32<<20)).Decode(out); err != nil {
			return fmt.Errorf("decode Docker response: %w", err)
		}
	}
	return nil
}

func (c *Client) Ping(ctx context.Context) error {
	if err := c.get(ctx, "/_ping", nil); err != nil {
		return err
	}
	var v struct {
		APIVersion    string `json:"ApiVersion"`
		MinAPIVersion string `json:"MinAPIVersion"`
	}
	if err := c.get(ctx, "/version", &v); err != nil {
		return err
	}
	selected, err := negotiateVersion(v.APIVersion, v.MinAPIVersion)
	if err != nil {
		return err
	}
	c.version = "v" + selected
	return nil
}
func negotiateVersion(server, minimum string) (string, error) {
	if _, err := parseVersion(server); err != nil {
		return "", fmt.Errorf("invalid Docker API version %q", server)
	}
	selected := server
	if compareVersion(selected, maxAPIVersion) > 0 {
		selected = maxAPIVersion
	}
	if minimum != "" && compareVersion(selected, minimum) < 0 {
		return "", fmt.Errorf("Docker requires API %s but DockSheriff supports up to %s", minimum, maxAPIVersion)
	}
	return selected, nil
}
func parseVersion(v string) ([2]int, error) {
	var out [2]int
	p := strings.Split(v, ".")
	if len(p) != 2 {
		return out, fmt.Errorf("invalid")
	}
	var e error
	out[0], e = strconv.Atoi(p[0])
	if e != nil {
		return out, e
	}
	out[1], e = strconv.Atoi(p[1])
	return out, e
}
func compareVersion(a, b string) int {
	x, ea := parseVersion(a)
	y, eb := parseVersion(b)
	if ea != nil || eb != nil {
		return -1
	}
	if x[0] != y[0] {
		return x[0] - y[0]
	}
	return x[1] - y[1]
}

func (c *Client) List(ctx context.Context, all bool) ([]dockerapi.Summary, error) {
	var v []dockerapi.Summary
	err := c.get(ctx, "/"+c.version+"/containers/json?all="+strconv.FormatBool(all), &v)
	return v, err
}
func (c *Client) Inspect(ctx context.Context, id string) (dockerapi.InspectResponse, error) {
	var v dockerapi.InspectResponse
	err := c.get(ctx, "/"+c.version+"/containers/"+url.PathEscape(id)+"/json", &v)
	return v, err
}
