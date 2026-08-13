package dockerapi

type ContainerConfig struct {
	Image string `json:"Image"`
	User  string `json:"User"`
}
type Mount struct {
	Type   string `json:"Type"`
	Source string `json:"Source"`
}
type DeviceMapping struct {
	PathOnHost string `json:"PathOnHost"`
}
type HostConfig struct {
	Privileged     bool            `json:"Privileged"`
	Mounts         []Mount         `json:"Mounts"`
	Binds          []string        `json:"Binds"`
	NetworkMode    string          `json:"NetworkMode"`
	PidMode        string          `json:"PidMode"`
	IpcMode        string          `json:"IpcMode"`
	UTSMode        string          `json:"UTSMode"`
	CgroupnsMode   string          `json:"CgroupnsMode"`
	CapAdd         []string        `json:"CapAdd"`
	SecurityOpt    []string        `json:"SecurityOpt"`
	Devices        []DeviceMapping `json:"Devices"`
	ReadonlyRootfs bool            `json:"ReadonlyRootfs"`
}
type Summary struct {
	ID string `json:"Id"`
}
type InspectResponse struct {
	Name       string           `json:"Name"`
	Config     *ContainerConfig `json:"Config"`
	HostConfig *HostConfig      `json:"HostConfig"`
	Mounts     []Mount          `json:"Mounts"`
}
