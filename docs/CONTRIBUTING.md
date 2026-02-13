# Contributing to Bug Hunter

> **Version:** 1.1.0  
> **Last Updated:** 2026-02-13  
> **Status:** Current

---

## Welcome!

Thank you for your interest in contributing to the Bug Hunter security research platform! This document provides guidelines and instructions for contributing.

---

## Getting Started

### Prerequisites

- **Go** 1.21+ (backend development)
- **Node.js** 18+ (frontend development)
- **Podman** or **Docker** (container runtime)
- **Git** 2.30+
- **Make** (optional, for convenience)

### Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/coppersec/bug-hunter.git
   cd bug-hunter
   ```

2. **Install dependencies:**
   ```bash
   # Backend
   cd app/dashboard/backend
   go mod tidy
   
   # Frontend
   cd ../frontend
   npm install
   
   # Tools
   cd ../../tools/
   ./install-all.sh  # If available
   ```

3. **Start the development environment:**
   ```bash
   # Start infrastructure services
   podman-compose up -d
   
   # Start dashboard backend
   cd app/dashboard/backend
   go run ./cmd/server/main.go
   
   # Start dashboard frontend (in another terminal)
   cd app/dashboard/frontend
   npm run dev
   ```

4. **Verify setup:**
   - Dashboard: http://localhost:3000
   - API: http://localhost:8080
   - Health check: http://localhost:8080/health

---

## Code Style

### Go

- Follow standard [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Use `gofmt` for formatting
- Run `golangci-lint` before committing
- Write comprehensive tests (target: 80% coverage)

```bash
# Format code
gofmt -w .

# Run linter
golangci-lint run

# Run tests
go test ./...
```

### JavaScript/TypeScript (Frontend)

- Follow [Vue Style Guide](https://vuejs.org/style-guide/)
- Use ESLint configuration provided
- Use Prettier for formatting
- Write component tests with Vitest

```bash
# Format code
npm run format

# Run linter
npm run lint

# Run tests
npm run test
```

### Python

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/)
- Use `black` for formatting
- Use `pylint` or `flake8` for linting
- Write tests with `pytest`

```bash
# Format code
black .

# Run linter
pylint tools/

# Run tests
pytest
```

### Containerfiles

- Use multi-stage builds where possible
- Minimize layer count
- Use specific versions, not `latest`
- Include health checks
- Document exposed ports

---

## Development Workflow

### 1. Sync With `main` and Create a Branch

```bash
git fetch origin
git checkout main
git pull --ff-only origin main
git checkout -b docs/short-description
```

**Branch naming conventions:**
- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `security/description` - Security fixes

### 2. Make Focused Changes

- Keep changes scoped to a single objective.
- Avoid unrelated formatting churn.
- Follow [Conventional Commits](https://www.conventionalcommits.org/):
  ```
  feat: add new scanner integration
  fix: resolve race condition in crawler
  docs: reorganize docs archive index
  refactor: simplify authentication middleware
  security: add input validation
  ```

### 3. Test What You Changed

```bash
# Preferred: run targeted tests first
cd app/dashboard/backend && go test ./...
cd app/dashboard/frontend && npm run test
cd tools/report-generation && pytest

# Optional full run if your scope is broad
make test
```

**Testing requirements:**
- [ ] Unit tests pass
- [ ] Integration tests pass (if applicable)
- [ ] Manual testing completed
- [ ] No regressions in existing functionality

### 4. Stage Intentionally (No `git add .`)

```bash
# Review changed files
git status --short

# Stage only intended files
git add docs/README.md docs/archive/README.md

# Verify staged diff before commit
git diff --staged
```

### 5. Commit and Push

```bash
git commit -m "docs: archive deprecated documents and refresh docs index"
git push origin docs/short-description
```

### 6. Create Pull Request

1. Open a PR from your branch.
2. Fill out the PR template completely.
3. Link related issues, for example: `Fixes #123`.
4. Request review from maintainers.

**PR Requirements:**
- [ ] Clear description of changes
- [ ] Tests included and passing (or explicitly marked not applicable)
- [ ] Documentation updated
- [ ] No merge conflicts
- [ ] Code review approved

### 7. Working in a Dirty Worktree

If your working tree has unrelated changes:

- Stage only files in your scope.
- Use `git diff --staged` to verify commit boundaries.
- Do not revert unrelated local changes that you did not create.

### 8. Documentation Archival Policy

When a doc is deprecated/superseded:

1. Move canonical content to `docs/archive/<topic>/`.
2. Leave a compatibility stub at the original path with a link to the new location.
3. Update `docs/archive/README.md` and `docs/README.md`.
4. Ensure links still resolve before opening the PR.

---

## Pull Request Process

### Review Criteria

Maintainers will review your PR for:

1. **Correctness** - Does it work as intended?
2. **Code Quality** - Clean, maintainable code
3. **Testing** - Adequate test coverage
4. **Documentation** - Clear and complete
5. **Security** - No security issues
6. **Performance** - Reasonable performance

### Addressing Review Comments

- Respond to all comments
- Make requested changes
- Push updates to the same branch
- Request re-review when ready

### Merge Requirements

- At least 1 approving review
- All CI checks passing
- No outstanding review comments
- Up-to-date with main branch

---

## Testing Guidelines

### Test Types

1. **Unit Tests** - Test individual functions
2. **Integration Tests** - Test component interactions
3. **End-to-End Tests** - Test full workflows
4. **Security Tests** - Test for vulnerabilities

### Writing Tests

```go
// Go example
func TestScanTarget(t *testing.T) {
    scanner := NewScanner(Config{Timeout: 30})
    
    result, err := scanner.Scan(Target{URL: "http://test.com"})
    
    if err != nil {
        t.Fatalf("unexpected error: %v", err)
    }
    
    if result.Status != "complete" {
        t.Errorf("expected status 'complete', got %s", result.Status)
    }
}
```

```javascript
// JavaScript example
describe('TargetForm', () => {
  it('submits form with valid data', async () => {
    const wrapper = mount(TargetForm)
    await wrapper.find('input[name="name"]').setValue('test.com')
    await wrapper.find('form').trigger('submit')
    
    expect(wrapper.emitted('submit')).toBeTruthy()
  })
})
```

### Test Coverage

- Minimum 80% coverage for new code
- Critical paths must have 100% coverage
- Use coverage reports to identify gaps

---

## Documentation Standards

### Code Comments

- Document public functions and types
- Explain complex algorithms
- Reference external resources
- Keep comments current with code

```go
// Scan performs a vulnerability scan on the target.
// It returns a channel of results and an error if initialization fails.
// The scan runs asynchronously and can be stopped via Stop().
func (s *Scanner) Scan(target Target) (<-chan Result, error) {
    // Implementation
}
```

### Markdown Documentation

- Use clear headings
- Include code examples
- Add tables for structured data
- Keep line length reasonable (<120 chars)

---

## Security Considerations

### Reporting Security Issues

- **DO NOT** open public issues for security bugs
- Email security@coppersec.io privately
- See project maintainers for current security disclosure procedures

### Secure Coding

- Validate all inputs
- Use parameterized queries
- Avoid logging sensitive data
- Follow OWASP guidelines
- Never commit secrets or API keys

---

## Areas for Contribution

### High Priority

- [ ] Scanner integrations (add new security tools)
- [ ] UI/UX improvements (dashboard frontend)
- [ ] Documentation (tutorials, guides)
- [ ] Test coverage (increase to 90%+)

### Medium Priority

- [ ] Performance optimizations
- [ ] Additional reconnaissance sources
- [ ] Report templates
- [ ] CI/CD improvements

### Good First Issues

- [ ] Bug fixes labeled `good-first-issue`
- [ ] Documentation improvements
- [ ] Code refactoring
- [ ] Test additions

---

## Questions?

- **General questions:** Open a Discussion
- **Bug reports:** Open an Issue
- **Security issues:** Email security@coppersec.io
- **Feature requests:** Open an Issue with `feature-request` label

---

## Recognition

Contributors will be:
- Listed in CONTRIBUTORS.md
- Mentioned in release notes
- Credited in documentation

Thank you for helping make security research more accessible!

---

*Copper Security Research Group - Contributing Guide v1.1.0*
