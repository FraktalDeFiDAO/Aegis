# Aegis Testing Documentation

## 1. Overview
Aegis uses a multi-layered testing strategy to ensure reliability and security:
- **Unit Tests:** Isolate individual functions and packages.
- **Integration Tests:** Verify communication between the Crawler and Scanner.
- **API Tests:** Ensure the REST interface behaves predictably.
- **Security Tests:** Validate regex patterns against known vulnerability signatures.

## 2. Running Tests
To run all tests locally:
```bash
go test -v ./...
```

To check code coverage:
```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## 3. Test Structure
- `internal/crawler/crawler_test.go`: Browser automation and link extraction logic.
- `internal/scanner/scanner_test.go`: Secret detection and vulnerability pattern matching.
- `internal/session/session_test.go`: Encrypted session persistence.
- `internal/recon/recon_test.go`: Web2/Web3 artifact discovery.
- `internal/api/api_test.go`: HTTP endpoint handlers.
- `internal/integration_test.go`: Full-stack "crawl-then-scan" workflow.

## 4. CI/CD Integration
Tests are automatically executed on every push to `main` or `develop` via Woodpecker CI.
The pipeline includes:
1. **Linting:** `golangci-lint`
2. **Security Scan:** `gosec`
3. **Unit & Integration Tests:** `go test` with race detection.

## 5. Coverage Thresholds
Aegis aims for a minimum of **80% code coverage** across all internal packages. Failure to meet this threshold will trigger a warning in the CI pipeline.
