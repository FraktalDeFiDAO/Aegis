# SPEC: Aegis Technical Specification

## 1. Architecture
- **Language:** Go 1.25+
- **Browser Core:** `rod` (DevTools Protocol) for high-performance browser automation.
- **Concurrency:** Worker pool pattern using Go channels for parallel crawling and scanning.
- **Storage:** AES-256 encrypted local storage for sensitive session data; local filesystem for mirrors and screenshots.
- **CI/CD:** Woodpecker CI (containerized) on Podman, managing the full lifecycle from linting to deployment.

## 2. Component Breakdown

### 2.1 Web Orchestration (internal/crawler)
- **Engine:** Headless browser management via `rod`.
- **Features:** Recursive link discovery, automated scrolling, screenshot capture, and custom User-Agent injection.
- **Session Management:** Integration with `internal/session` for authenticated state persistence.

### 2.2 Security Analysis (internal/scanner)
- **Engines:** Regex-based pattern matching for secrets and dangerous JS patterns.
- **Targeting:** ATO (Account Takeover), Session Exposure, XSS, and Open Redirects.
- **Performance:** Parallel file processing using a multi-worker coordinator.

### 2.3 Intelligence & Recon (internal/intel, internal/recon)
- **Threat Intel:** Automated ingestion of external feeds (e.g., URLHaus) for real-time risk assessment.
- **Web2 Recon:** DNS-based discovery, subdomain enumeration, and port scanning.
- **Web3 Recon:** Blockchain artifact detection (EVM addresses, ENS domains) and network identification.

### 2.4 Reliability & Safety (internal/validator, internal/response)
- **Validator:** Strict URL and path sanitization to prevent injection and traversal.
- **Response Handler:** Webhook-based automation for incident alerts and remediation triggers.

## 3. Testing Framework
### 3.1 Unit Testing
- Minimum **80% branch coverage** enforced for critical paths.
- Mocking of network and filesystem dependencies.
- Location: `internal/**/*_test.go`.

### 3.2 Integration & E2E Testing
- Full workflow validation: "Mock Server -> Crawl -> Scan -> Finding Detection".
- API endpoint validation using `httptest`.
- Location: `internal/integration_test.go`.

## 4. Automation & CI/CD (`.woodpecker.yaml`)
### 4.1 Stages
1. **Lint:** Enforce code quality via `golangci-lint`.
2. **Security Scan:** Identify vulnerabilities in code via `gosec`.
3. **Test:** Execute unit/integration tests with race detection and coverage reporting.
4. **Build:** Generate containerized artifacts using Podman.
5. **Deploy:** Automated rollout to staging environments.

## 5. Deployment Targets
- **Staging:** Local Podman-compose environment for integration verification.
- **Production:** Hardened containerized environment with encrypted volume mounts.