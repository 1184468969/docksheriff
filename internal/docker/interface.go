// Package docker provides DockSheriff's complete Docker Engine access surface.
package docker

import (
	"context"
)

// Ping deliberately exposes no Engine-provided data because the application
// needs only success or failure from the health check.
type Ping struct{}

// Version is the safe subset of server-version metadata used in reports.
type Version struct {
	Version    string
	APIVersion string
}

type ListOptions struct{ All bool }

// ContainerSummary carries only the opaque identifier required to request the
// corresponding Inspect response. The application never renders this value.
type ContainerSummary struct{ ID string }

// Container is the complete Engine-to-audit data boundary. It intentionally
// has no environment, label, annotation, raw JSON, command, or ID fields. The
// list identifier above is kept separate and used only as an Inspect target.
type Container struct {
	Platform         string
	Name             string
	Config           *ContainerConfig
	HostConfig       *ContainerHostConfig
	BindMountSources []string
}

type ContainerConfig struct {
	Image string
	User  string
}

type ContainerHostConfig struct {
	Privileged             bool
	NetworkMode            string
	PIDMode                string
	IPCMode                string
	UTSMode                string
	CgroupNamespaceMode    string
	CapabilitiesAdded      []string
	SecurityOptions        []string
	HasDeviceAccess        bool
	ReadonlyRootFilesystem bool
}

// Engine intentionally exposes only the read-only calls used by DockSheriff.
// Adding a method is a security-sensitive API change.
type Engine interface {
	Ping(context.Context) (Ping, error)
	ServerVersion(context.Context) (Version, error)
	ContainerList(context.Context, ListOptions) ([]ContainerSummary, error)
	ContainerInspect(context.Context, string) (Container, error)
}

// Metadata describes the effective connection without exposing credentials.
type Metadata struct {
	Endpoint    string
	InsecureTCP bool
}
