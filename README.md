# DockSheriff

Human-friendly security checks for running Docker containers.

DockSheriff performs 15 read-only checks against container configuration and explains actionable risks. It only sends `GET` requests for Docker ping, server version, container listing, and container inspection. It never executes commands, mutates containers, prints environment variables or arbitrary labels, sends telemetry, or contacts the internet.

> DockSheriff complements image and host scanners such as Trivy, Dockle, and Docker Bench. It focuses narrowly on the effective configuration of containers that already exist.

```sh
go install github.com/1184468969/docksheriff/cmd/docksheriff@latest
docksheriff --fail-on high
docksheriff inspect portainer
docksheriff explain DS002
docksheriff rules
```

Use `--format json`, `--all`, `--ignore DS012`, `--min-severity low`, or `--host unix:///var/run/docker.sock` as needed. Exit status is 0 for success, 1 when `--fail-on` is reached, and 2 for usage or Docker errors.

By default, only Medium and higher findings are expanded in terminal output; all severities remain in the summary and JSON output. `tcp://` and `http://` Docker endpoints produce DS015. HTTPS supports the standard `DOCKER_CERT_PATH` files (`ca.pem`, `cert.pem`, and `key.pem`). Docker API calls have a ten-second deadline.

## Development

The tests use fixtures and local HTTP test servers; they do not need a Docker daemon or privileged containers.

```sh
go test ./...
go test -race ./...
go vet ./...
go build ./cmd/docksheriff
```

Licensed under Apache-2.0.
