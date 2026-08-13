# DockSheriff contributor instructions

DockSheriff is a read-only Docker security checker. Never add Docker write operations, exec/cp, environment or arbitrary-label output, telemetry, or network access other than the configured Docker Engine endpoint. Treat all Engine strings as untrusted and sanitize terminal output. Every Engine request needs a timeout. Tests must not require Docker or privileged containers.

Run `gofmt -w`, `go test ./...`, `go test -race ./...`, and `go vet ./...` before committing.

