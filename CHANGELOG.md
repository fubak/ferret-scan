# Changelog

All notable changes to ferret-scan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned Features
- VS Code extension for IDE integration
- CI/CD plugins for Jenkins, GitLab, Azure DevOps
- REST API for third-party integrations
- Machine learning model for advanced anomaly detection
- Compliance framework integration (SOC2, ISO27001)
- Community rule marketplace
- Advanced threat hunting capabilities
- SIEM/SOAR integrations

## [1.0.8] - 2026-02-04

### Security
- Fixed ReDoS vulnerabilities in regex patterns (CWE-1333)
- Fixed path traversal in file operations (CWE-22)
- Fixed arbitrary file write via auto-remediation (CWE-73)
- Added JSON schema validation for all configuration files (CWE-502)
- Cleaned up HTML escaping implementation (CWE-79)
- Updated outdated dependencies with known vulnerabilities (CWE-1395)
- Added rate limiting on regex execution (CWE-400)
- Added baseline file integrity checks with checksums (CWE-345)

### Added
- **Capability Mapping** - Maps AI agent capabilities and detects escalation risks
- **Custom Rules** - Create and manage custom detection rules
- **Dependency Risk Analysis** - Analyzes package dependencies for security risks
- **Entropy Analysis** - Detects secrets using entropy-based analysis
- **Granular Exit Codes** - Detailed exit codes for CI/CD integration
- **Git Hooks Integration** - Pre-commit and pre-push security scanning
- **Ignore Comments** - Inline comment-based finding suppression
- **Interactive TUI** - Terminal-based interactive scanning interface
- **MCP Validator** - Model Context Protocol configuration validation
- **Policy Enforcement** - Organizational security policy enforcement
- **Scan Diff** - Compare scans and detect regressions
- **Webhooks** - Send scan results to external services
- JSON Schema for ferret configuration (`ferret-config.schema.json`)
- Path security utility for containment validation
- Zod schema validation for JSON configurations
- Audit logging for baseline operations

### Changed
- Improved HTML reporter with better XSS prevention
- Enhanced threat feed with validation
- Optimized regex patterns to prevent catastrophic backtracking
- Added match count and timeout limits to PatternMatcher

### Documentation
- Added `SECURITY_ANALYSIS.md` - Full vulnerability analysis report
- Added `REMEDIATION_PLAN.md` - Detailed remediation implementation plan

## [1.0.7] - 2026-02-01

### Fixed
- Async file discovery for spinner animation during discovery phase
- Both "Discovering files..." and "Scanning..." spinners now animate smoothly

## [1.0.6] - 2026-02-01

### Fixed
- Async file reading (`fs.promises.readFile`) for spinner animation during scan phase
- Spinner now animates during file scanning on large codebases

## [1.0.5] - 2026-02-01

### Fixed
- Time-based yielding (every 100ms) for more reliable spinner updates

## [1.0.4] - 2026-02-01

### Fixed
- Yield on every file for spinner animation (intermediate fix)

## [1.0.3] - 2026-02-01

### Fixed
- Increased yield frequency for spinner updates

## [1.0.2] - 2026-02-01

### Added
- Progress indicators during scanning using ora spinner
- Real-time file count and findings display during scan
- TTY detection to disable spinners in CI environments

## [1.0.1] - 2026-01-31

### Fixed
- Repository URLs corrected from `ferret-security/ferret-scan` to `fubak/ferret-scan`
- Added `typescript` as production dependency (required at runtime for AST analysis)

## [1.0.0] - 2026-01-31

### Added
- Initial release of Ferret Security Scanner
- Core security scanning engine with 65+ rules across 9 threat categories
- Support for Claude Code configuration files (.claude/, CLAUDE.md, skills/, hooks/)
- AI-specific threat detection (prompt injection, jailbreaks, social engineering)
- Multiple output formats (Console, JSON, SARIF, HTML)
- Watch mode for real-time monitoring
- Baseline management for accepted findings
- Enhanced CLI with comprehensive commands
- Semantic analysis engine with TypeScript AST parsing
- Cross-file correlation analysis for multi-file attack patterns
- Threat intelligence integration with IoC matching
- Auto-remediation engine with safe fixes and quarantine system
- GitHub Actions workflow for CI/CD integration
- Docker containerization with security hardening
- Comprehensive test suite with 99.2% false positive reduction

### Security
- Non-root container execution
- Read-only filesystem in production containers
- Dropped Linux capabilities for minimal attack surface
- Secure handling of sensitive pattern matching
- Safe auto-remediation with backup and rollback capabilities

### Performance
- Optimized pattern matching with caching
- Resource monitoring and memory limits
- Lazy loading of AI models and threat feeds
- Parallel processing for large codebases
- Efficient file discovery with ignore patterns