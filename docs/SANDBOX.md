# Podman-in-Podman Sandbox

Project Aegis executes inside a nested Podman environment. The outer container provides Podman/Podman Compose, while the compose stack below spins up the authenticated crawler + audit helpers inside inner containers.

## Outer sandbox container

1. Build the sandbox image once from the repository root:

   ```sh
   podman build -f sandbox/Containerfile -t aegis-sandbox .
   ```

2. Run the container with the repository mounted so Podman Compose sees the `compose/` directory. You also need `--privileged` (or similar) so the inner Podman daemon can create containers, and bind-mount `/var/lib/containers` or `/run/podman` when you want to reuse existing storage.

   ```sh
   podman run --privileged --rm -it \
     -v "$PWD":/workspace:z \
     -v /var/lib/containers:/var/lib/containers:z \
     aegis-sandbox
   ```

   The entrypoint will default to `podman compose -f compose/podman-compose.yml up --build`. From this shell you can also run `podman ps`/`podman compose ps` to inspect the inner services.

## Toolchain wrappers

- The container installs `/usr/local/bin/go`, `/usr/local/bin/rust`, `/usr/local/bin/python`, and `/usr/local/bin/node`. Each wrapper calls `toolchain-runner`, which proxies to the corresponding official image via `podman run --rm --pull=missing`. Run them as if the toolchains were native (`go version`, `rust --version`, `python -m pip --version`, `node --version`), and they operate from `/workspace` so your repository files are available.
- When you need to script multiple languages, invoke `toolchain-runner <tool> ...` directly (e.g., `toolchain-runner python -m pytest ./...`) to reuse the same mounting logic.

## Inner compose stack

- `compose/podman-compose.yml` defines three services that reuse the same Go binary:
  * `aegis-auth` runs `aegis auth` to capture `session_lock.json` inside `data/session`.
  * `aegis-crawl` runs `aegis crawl` and writes mirrors into `data/dump`, consuming `config.yaml` (at the repository root) for discovery options.
  * `aegis-scan` runs `aegis scan` against the mirrored dump.

All services share the `bug-hunter/aegis:latest` image built from `compose/Containerfile`, which compiles `cmd/aegis`. The commands are now fully implemented with authentication capture, web crawling, and security scanning capabilities.

## Data directories

- `data/session` holds `session_lock.json` and is mapped read-write into the services.
- `data/dump` is the target directory for the mirrored assets and is passed read-only into `aegis-scan`.

You can seed these directories on the host, inspect them during development, or mount additional files as needed.

## Running the Go toolchain

- Use `scripts/go-run.sh` so Go, `gofmt`, and `go test` execute inside the official Go 1.25 runtime instead of relying on a local toolchain:

  ```sh
  scripts/go-run.sh gofmt -w cmd ./session
  scripts/go-run.sh go test ./...
  scripts/go-run.sh go mod tidy
  ```

  Passing the repository root as `/src` lets the container read/write `go.mod`/`go.sum` and allows you to build/cache dependencies cleanly before the Podman Compose build step.

## Development workflow

1. Inside the outer sandbox container, run `podman compose -f compose/podman-compose.yml up --build` (the entrypoint already does this by default).
2. To regenerate the binary after editing Go code, exit the compose run, rebuild the image (`podman compose build aegis-auth`), and rerun the stack.
3. The Go binary depends on `github.com/go-rod/rod`, `github.com/ysmood/gson`, `github.com/spf13/cobra`, and `gopkg.in/yaml.v3`. Run `go mod tidy` on the host once you have Go 1.25 available; that will populate `go.sum` before inner builds occur.

## Security Considerations

### Current State (Local Development)
This tool is currently designed for local, single-developer environments. The following security considerations apply:

- Session data is stored in plain text format
- No encryption of sensitive authentication tokens
- Default file paths are used for session and dump storage

### Planned Improvements (Remote Deployment)
Before deploying to remote servers, the following security enhancements will be implemented:

- **Session Encryption**: Encrypt session data to protect sensitive authentication tokens
- **Input Validation**: Add robust input validation to prevent path traversal and injection attacks
- **Secure Defaults**: Implement secure default paths and permissions
- **Privilege Reduction**: Minimize container privileges required for operation
