# Project Aegis

Project Aegis is an authenticated web crawler and security scanner designed to identify potential vulnerabilities and exposed secrets in web applications.

## Features

- **Authentication Capture**: Captures and persists authenticated browser sessions
- **Web Crawling**: Discovers and mirrors web application content up to a configurable depth
- **Security Scanning**: Analyzes mirrored content for potential security issues and exposed secrets

## Commands


### Auth
Captures and persists the authenticated browser session:

```bash
aegis auth --session /path/to/session/file
```

### Crawl
Runs the discovery spider against the target application:

```bash
aegis crawl --config /path/to/config.yaml --dump /path/to/dump/dir --session /path/to/session/file
```

### Scan
Analyzes the mirrored dump for secrets and dangerous artifacts:

```bash
aegis scan --input /path/to/dump/dir
```

### Exploit
Run targeted ATO (Account Takeover) simulations and multi-instance exploit chains:

```bash
aegis exploit --config ./configs/ato_scenario.yaml
```

See the [ATO Guide](ATO_GUIDE.md) for detailed configuration instructions.

## Configuration

The crawler uses a YAML configuration file with the following options:

```yaml
target: https://example.local      # Target URL to crawl
maxDepth: 3                        # Maximum depth to crawl
userAgent: "Project-Aegis/1.0"     # User agent string to use
```

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


## Architecture

- **Main Command**: Orchestrates the auth, crawl, and scan workflows using Cobra
- **Session Manager**: Handles capturing and restoring browser sessions (cookies, localStorage, sessionStorage)
- **Crawler**: Discovers and mirrors web application content
- **Scanner**: Analyzes content for potential security issues

## Building

To build the project:

```bash
# Using the provided script to run in a consistent Go environment
./scripts/go-run.sh go build -o aegis ./cmd/aegis
```

## Running with Podman Compose

The project includes a Podman Compose configuration for containerized execution:

```bash
podman-compose -f compose/podman-compose.yml up --build
```

## Development

For development, use the provided sandbox environment:

```bash
# Build the sandbox container
podman build -f sandbox/Containerfile -t aegis-sandbox .

# Run in the sandbox environment
podman run --privileged --rm -it \
  -v "$PWD":/workspace:z \
  -v /var/lib/containers:/var/lib/containers:z \
  aegis-sandbox
```

## Security Scan Capabilities

The scanner currently detects:

- API keys and secrets
- Passwords and credentials
- JWT tokens
- AWS/GCP/other cloud provider keys
- Private keys
- Dangerous JavaScript patterns (eval, innerHTML, unsafe redirects)
- Inline scripts

## Future Enhancements

- Enhanced authentication automation
- More sophisticated crawling algorithms
- Additional security checks
- Performance optimizations
- Better reporting formats