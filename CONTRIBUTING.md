# Contributing to Ferret Security Scanner

Thank you for your interest in contributing to Ferret! This document provides guidelines and instructions for contributing to the project.

## 🤝 Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## 🚀 Getting Started

### Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0
- Git
- TypeScript knowledge
- Understanding of security concepts

### Development Setup

1. **Fork and Clone**

```bash
git clone https://github.com/YOUR-USERNAME/ferret-scan.git
cd ferret-scan
```

2. **Install Dependencies**

```bash
npm install
```

3. **Build Project**

```bash
npm run build
```

4. **Run Tests**

```bash
npm test
```

5. **Start Development Mode**

```bash
npm run dev
```

### Project Structure

```
ferret-scan/
├── src/                   # Source code
│   ├── analyzers/         # Core analysis engines
│   ├── intelligence/      # Threat intelligence
│   ├── remediation/       # Auto-fix functionality
│   ├── reporters/         # Output formatters
│   ├── rules/            # Security rules
│   └── utils/            # Utilities
├── test/                 # Test files
├── bin/                  # CLI executable
├── docs/                 # Documentation
└── docker/               # Docker configurations
```

## 🔍 Types of Contributions

### 1. Security Rules

**Adding new threat detection rules**

Create rules in `src/rules/` following this pattern:

```typescript
export const newRule: Rule = {
  id: 'category-threat-001',
  name: 'Descriptive Threat Name',
  description: 'Clear description of what this detects',
  category: 'injection' | 'credentials' | 'exfiltration' | /* ... */,
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW',
  patterns: [
    {
      type: 'regex',
      pattern: 'your-detection-pattern',
      flags: 'gi'
    }
  ],
  falsePositiveFilters: [
    {
      type: 'context',
      pattern: 'legitimate-use-pattern'
    }
  ],
  references: [
    'https://example.com/threat-documentation'
  ],
  metadata: {
    cwe: 'CWE-79',
    mitre: 'T1059',
    confidence: 0.9
  }
};
```

### 2. Bug Fixes

**Steps for bug fixes:**

1. Create an issue describing the bug
2. Create a branch: `git checkout -b fix/bug-description`
3. Write a failing test that reproduces the bug
4. Fix the bug
5. Ensure all tests pass
6. Submit a pull request

### 3. Feature Enhancements

**For new features:**

1. Create an issue with feature proposal
2. Discuss design and implementation
3. Create feature branch: `git checkout -b feature/feature-name`
4. Implement with tests and documentation
5. Submit pull request

### 4. Documentation

**Documentation improvements:**

- README updates
- API documentation
- Configuration guides
- Tutorial content
- Code comments

## 🧪 Testing Guidelines

### Test Requirements

All contributions must include tests:

```typescript
// test/rules/new-rule.test.ts
import { newRule } from '../../src/rules/new-rule';
import { testRule } from '../utils/rule-tester';

describe('New Rule', () => {
  it('should detect malicious pattern', () => {
    const result = testRule(newRule, 'malicious content');
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].severity).toBe('HIGH');
  });

  it('should not flag legitimate use', () => {
    const result = testRule(newRule, 'legitimate content');
    expect(result.findings).toHaveLength(0);
  });
});
```

### Running Tests

```bash
# Run all tests
npm test

# Run tests with coverage
npm run test:coverage

# Run tests in watch mode
npm run test:watch

# Run specific test file
npm test -- new-rule.test.ts
```

### Test Categories

1. **Unit Tests**: Test individual functions/classes
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test CLI functionality
4. **Security Tests**: Test security rule effectiveness

## 📝 Coding Standards

### TypeScript Guidelines

```typescript
// Use explicit types
function processFile(filePath: string): ScanResult {
  // implementation
}

// Use interfaces for object types
interface ScanOptions {
  readonly severity: Severity;
  readonly includePatterns: string[];
}

// Use enums for constants
enum Severity {
  Critical = 'CRITICAL',
  High = 'HIGH',
  Medium = 'MEDIUM',
  Low = 'LOW'
}
```

### Code Style

- Use ESLint configuration provided
- Follow existing naming conventions
- Write meaningful variable names
- Add JSDoc comments for public APIs
- Keep functions small and focused

### Linting

```bash
# Check linting
npm run lint

# Fix automatically fixable issues
npm run lint:fix
```

## 🔒 Security Considerations

### Security Rule Development

1. **Validate Patterns**: Ensure regex patterns are safe and don't cause ReDoS
2. **Test False Positives**: Minimize false positives with proper filters
3. **Document Threats**: Provide clear threat descriptions and references
4. **Test Coverage**: Include both positive and negative test cases

### Sensitive Data

- Never commit real API keys, passwords, or credentials
- Use placeholder values in test fixtures
- Sanitize any logs or error messages

### Performance

- Test rule performance with large files
- Avoid exponential regex patterns
- Cache expensive operations
- Monitor memory usage

## 📋 Pull Request Process

### Before Submitting

1. **Update Documentation**: Update relevant docs
2. **Add Tests**: Ensure 100% test coverage for new code
3. **Check Linting**: Run `npm run lint`
4. **Run Tests**: All tests must pass
5. **Update Changelog**: Add entry to CHANGELOG.md

### PR Template

When creating a PR, include:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] All tests pass
- [ ] New tests added
- [ ] Manual testing completed

## Security Impact
- [ ] No security implications
- [ ] Security review required
- [ ] New security rules added

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Changelog updated
```

### Review Process

1. **Automated Checks**: GitHub Actions run automatically
2. **Code Review**: Maintainers review code quality
3. **Security Review**: Security implications assessed
4. **Testing**: Additional testing if needed
5. **Merge**: Approved PRs are merged

## 🌟 Recognition

### Contributors

All contributors are recognized in:
- README.md contributors section
- GitHub contributors page
- Release notes for significant contributions

### Maintainer Path

Active contributors may be invited to become maintainers based on:
- Quality of contributions
- Understanding of project goals
- Community involvement
- Security expertise

## 📞 Getting Help

### Community Support

- **GitHub Discussions**: Ask questions and share ideas
- **Issues**: Report bugs or request features
- **Discord**: Join our community chat (link in README)

### Development Questions

- Tag maintainers in GitHub for urgent questions
- Use GitHub Discussions for general development questions
- Join our weekly contributor calls (schedule in Discord)

## 🎯 Contribution Ideas

### Good First Issues

Look for issues labeled:
- `good first issue`: Perfect for new contributors
- `help wanted`: Community help needed
- `documentation`: Documentation improvements
- `enhancement`: Feature requests

### Advanced Contributions

- Performance optimizations
- New output formats
- Advanced detection algorithms
- Integration with security tools
- Machine learning models

## 📜 Legal

### License Agreement

By contributing, you agree that your contributions will be licensed under the MIT License.

### Copyright

- Retain original copyright notices
- Add your copyright for significant new files
- Follow existing copyright patterns

## 🚀 Development Workflow

### Branch Strategy

```bash
# Main branches
main          # Stable releases
develop       # Integration branch

# Feature branches
feature/name  # New features
fix/name      # Bug fixes
docs/name     # Documentation
security/name # Security fixes
```

### Commit Messages

Follow conventional commits:

```bash
feat: add new threat detection rule for API key exposure
fix: resolve false positive in credential detection
docs: update installation instructions
test: add integration tests for SARIF output
security: patch regex DoS vulnerability
```

### Release Process

1. **Feature Freeze**: No new features, only fixes
2. **Testing**: Comprehensive testing phase
3. **Security Review**: Security audit of changes
4. **Documentation**: Update all documentation
5. **Release**: Tagged release with changelog

## 🎉 Thank You!

Your contributions make Ferret better for everyone. Whether it's a small bug fix or a major feature, every contribution is valuable.

For questions about contributing, reach out to the maintainers or ask in GitHub Discussions.

Happy coding! 🦫