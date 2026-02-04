# Aegis New Security Scanning Modules

This document describes the new security scanning modules added to Aegis as part of the enhanced security flow implementation.

## Overview

The new modules implement the proposed security scanning flow with the following components:

1. **Exploitable Software Scanner** - Detects known-vulnerable software (Redis, MongoDB/Mongobleed)
2. **OWASP Top 25 Scanner** - Structured scanning for OWASP categories
3. **Platform Detector** - Framework detection (React, Vue, Svelte, Angular) with versioning
4. **Content Acquirer** - Platform-aware content acquisition (static vs rendered)
5. **Unified Scanner** - Integration layer combining all capabilities

## Module Structure

```
app/aegis/internal/
├── exploitable/
│   ├── scanner.go       # Main exploitable scanner interface
│   ├── redis.go         # Redis/Mongobleed detection
│   └── mongodb.go       # MongoDB/Mongobleed detection
├── owasp25/
│   ├── categories.go    # OWASP Top 25 category definitions
│   └── scanner.go       # OWASP vulnerability scanner
├── platform/
│   └── detector.go      # Framework and platform detection
├── content/
│   └── acquisition.go   # Platform-aware content acquisition
└── integration/
    └── scanner.go       # Unified scanner integration
```

## Module Details

### 1. Exploitable Package (`internal/exploitable`)

Detects known-vulnerable software versions and configurations.

#### Features:
- **Redis Scanner**
  - CVE-2025-XXXX (Mongobleed) detection
  - Unauthorized CONFIG command access
  - Lua sandbox escape attempts
  - Version fingerprinting
  - TLS support

- **MongoDB Scanner**
  - Mongobleed vulnerability detection (Dec 2025)
  - Unauthenticated access detection
  - Default credential testing
  - Version-based vulnerability checking
  - Database enumeration (if accessible)

#### Usage:
```go
import "github.com/coppertone/bug-hunter/app/aegis/internal/exploitable"

// Create scanner
scanner := exploitable.NewScanner(
    exploitable.WithTimeout(10 * time.Second),
    exploitable.WithWorkers(10),
)

// Scan target
findings := scanner.ScanTarget("192.168.1.1", []int{6379, 27017})

// Or scan network
findings, _ := scanner.ScanNetwork("192.168.1.0/24")
```

### 2. OWASP25 Package (`internal/owasp25`)

Structured scanning for OWASP Top 25 vulnerabilities.

#### Features:
- OWASP Top 10 2021 categories:
  - A01: Broken Access Control
  - A02: Cryptographic Failures
  - A03: Injection
  - A04: Insecure Design
  - A05: Security Misconfiguration
  - A06: Vulnerable Components
  - A07: Auth Failures
  - A08: Integrity Failures
  - A09: Logging Failures
  - A10: SSRF
- Pattern-based detection
- CVSS scoring per finding
- CWE mapping
- Remediation guidance

#### Usage:
```go
import "github.com/coppertone/bug-hunter/app/aegis/internal/owasp25"

// Create scanner
scanner := owasp25.NewScanner("/path/to/scan")

// Full scan
findings, _ := scanner.Scan()

// Scan string content
findings = scanner.ScanString(htmlContent, "source.html")

// Get statistics
stats := scanner.GetCategoryStats(findings)
report := scanner.Report(findings)
```

### 3. Platform Package (`internal/platform`)

Framework and platform detection with version extraction.

#### Features:
- **Frontend Frameworks**
  - React (with version detection)
  - Vue.js (with version detection)
  - Svelte
  - Angular
  - Preact, SolidJS, Alpine.js
  - jQuery

- **Backend Detection**
  - Express.js, Django, Rails, Laravel
  - Spring, ASP.NET

- **CMS Detection**
  - WordPress (with plugin detection)
  - Drupal, Joomla
  - Shopify, Magento

- **Platform Type Classification**
  - Static Site
  - SPA (Single Page Application)
  - SSR (Server-Side Rendered)
  - Hybrid

#### Usage:
```go
import "github.com/coppertone/bug-hunter/app/aegis/internal/platform"

// Create detector
detector := platform.NewDetector(30 * time.Second)

// Detect platform
detection, _ := detector.Detect("https://example.com")

// Check results
if detection.IsSPA() {
    // Use browser rendering
}

for _, fw := range detection.Frameworks {
    fmt.Printf("Found: %s v%s (confidence: %d%%)\n", 
        fw.Name, fw.Version, fw.Confidence)
}
```

### 4. Content Package (`internal/content`)

Platform-aware content acquisition.

#### Features:
- **Auto-Detection Strategy**
  - Detects platform type first
  - Uses static HTTP for static sites
  - Uses Rod (headless Chrome) for SPAs

- **Static Acquisition**
  - Fast HTTP requests
  - Custom headers
  - Timeout control

- **Rendered Acquisition**
  - Headless browser (Rod)
  - JavaScript execution
  - Network call monitoring
  - Console log capture

#### Usage:
```go
import "github.com/coppertone/bug-hunter/app/aegis/internal/content"

// Create acquirer with auto-detection
acquirer, _ := content.NewAcquirer()
defer acquirer.Close()

// Acquire content (auto-detects strategy)
content, _ := acquirer.Acquire("https://example.com")

// Or force specific strategy
acquirer, _ = content.NewAcquirer(
    content.WithStrategy(content.StaticOnly),
)

// Batch acquisition
contents, _ := acquirer.AcquireBatch(urls, false)
```

### 5. Integration Package (`internal/integration`)

Unified scanner combining all capabilities.

#### Features:
- Concurrent scanning
- Unified finding format
- Statistics generation
- Batch scanning

#### Usage:
```go
import "github.com/coppertone/bug-hunter/app/aegis/internal/integration"

// Create unified scanner
scanner, _ := integration.NewUnifiedScanner(
    integration.WithExploitable(true),
    integration.WithOWASP(true),
    integration.WithContent(true),
)
defer scanner.Close()

// Define target
target := integration.Target{
    URL:   "https://example.com",
    Host:  "192.168.1.1",
    Ports: []int{80, 443, 6379, 27017},
}

// Scan
findings, _ := scanner.ScanTarget(target)

// Statistics
stats := scanner.GetStatistics(findings)
```

## Integration with Existing Aegis

The new modules integrate seamlessly with existing Aegis components:

### Replacing react-detector:
```go
// Old
detector := react_detector.New()
detector.Detect(url)

// New
detector := platform.NewDetector(timeout)
detection, _ := detector.Detect(url)
// detection.Frameworks contains all detected frameworks
```

### Enhancing scanner:
```go
// Existing scanner focuses on secrets and patterns
existingScanner := scanner.NewScanner(dumpPath)
findings, _ := existingScanner.Scan()

// New OWASP scanner adds structured categories
owaspScanner := owasp25.NewScanner(dumpPath)
owaspFindings, _ := owaspScanner.Scan()
```

### Replacing mongo-scanner:
```go
// Old (separate tool)
./mongo-scanner -t target.com

// New (integrated)
scanner := exploitable.NewScanner()
findings := scanner.ScanTarget("target.com", []int{27017})
```

## Configuration

All modules support configuration through functional options:

```go
// Timeout configuration
exploitable.NewScanner(exploitable.WithTimeout(30 * time.Second))
owasp25.NewScanner(path, owasp25.WithWorkers(20))

// Feature toggles
integration.NewUnifiedScanner(
    integration.WithExploitable(true),
    integration.WithOWASP(true),
    integration.WithContent(true),
)
```

## Security Considerations

1. **Responsible Disclosure**: These tools detect vulnerabilities but do not exploit them
2. **Rate Limiting**: Built-in timeouts and rate limiting to avoid overwhelming targets
3. **Authentication**: Support for authenticated scanning where applicable
4. **TLS Verification**: Configurable TLS verification for HTTPS connections

## Future Enhancements

- [ ] Elasticsearch exploitable scanner
- [ ] Jenkins vulnerability scanner
- [ ] Kubernetes API scanner
- [ ] Docker Registry scanner
- [ ] CVSS 4.0 support
- [ ] Machine learning for anomaly detection
- [ ] CI/CD pipeline integration

## Testing

Run tests for all modules:
```bash
cd app/aegis
go test ./internal/exploitable/... -v
go test ./internal/owasp25/... -v
go test ./internal/platform/... -v
go test ./internal/content/... -v
go test ./internal/integration/... -v
```

## License

Same as Aegis project.
