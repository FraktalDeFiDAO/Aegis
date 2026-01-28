# Implementation Plan for Aegis Fixes

## Phase 1: Critical Bug Fixes (Day 1)
### 1. Fix Scanner Test Compilation Error
- **File**: `/internal/scanner/scanner_test.go`
- **Action**: Add missing `import "strings"` to the imports section
- **Test**: Verify the test compiles and runs successfully

### 2. Fix Crawler Screenshot Bug
- **File**: `/internal/crawler/crawler.go`
- **Issue**: In the `processPage` function, the screenshot logic incorrectly calls `page.Screenshot()` twice
- **Current problematic code**:
  ```go
  if c.config.EnableScreenshot {
      shotPath := filepath.Join(c.config.ScreenshotPath, generateFilename(urlStr, ".png"))
      if err := page.Screenshot(true, &proto.PageCaptureScreenshot{
          Format: proto.PageCaptureScreenshotFormatPng,
      }); err == nil {
          // Page.Screenshot returns []byte, need to write it
          img, _ := page.Screenshot(true, nil)
          os.WriteFile(shotPath, img, 0644)
      }
  }
  ```
- **Fix**: Capture the screenshot data once and save it properly

## Phase 2: Security Improvements (Day 2)
### 1. Replace Hardcoded Development Key
- **File**: `/internal/session/manager.go`
- **Issue**: Uses fallback key when no key provided
- **Solution**: Generate a random key or require explicit key provision
- **Change**: Modify `NewSessionManager` to handle missing keys more securely

### 2. Improve Input Validation
- **File**: `/internal/crawler/crawler.go`
- **Function**: `generateFilename`
- **Issue**: Potential path traversal vulnerability
- **Solution**: Add proper sanitization to prevent directory traversal

## Phase 3: Test Coverage (Day 3-4)
### 1. Add Tests for Missing Packages
- **intel package**: Create `intel/intel_test.go` with tests for IntelManager
- **response package**: Create `response/response_test.go` with tests for response handlers
- **logger package**: Create `logger/logger_test.go` with tests for logger functionality
- **api package**: Expand tests to cover all endpoints

### 2. Improve Existing Tests
- Add negative test cases
- Add edge case testing
- Add integration tests

## Phase 4: Documentation and Code Quality (Day 5)
### 1. Add Missing Documentation
- Add godoc comments to exported functions/types
- Improve existing documentation clarity

### 2. Code Quality Improvements
- Standardize error handling patterns
- Remove magic numbers/strings
- Add proper resource cleanup

## Implementation Steps

### Step 1: Create Git Branch
```bash
git checkout -b aegis-audit-fixes
```

### Step 2: Apply Critical Bug Fixes
1. Fix scanner test
2. Fix crawler screenshot bug

### Step 3: Apply Security Improvements
1. Secure session key handling
2. Improve input validation

### Step 4: Add Missing Tests
1. Create test files for missing packages
2. Expand existing test coverage

### Step 5: Documentation and Cleanup
1. Add documentation
2. Refactor for code quality

### Step 6: Commit Changes
```bash
git add .
git commit -m "Apply fixes and improvements from audit findings"
```

## Verification Process
1. Run all existing tests to ensure no regressions
2. Run the newly added tests
3. Manually verify critical functionality
4. Perform security review of changes