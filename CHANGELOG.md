# Changelog

All notable changes to ferret-scan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

## [1.0.9] - 2026-02-04

### Added
- **Git Hooks Integration** - Pre-commit and pre-push hooks for automatic security scanning (`ferret hooks install`)
- **Custom Rules Engine** - Define custom security rules via YAML/JSON for organization-specific patterns
- **Entropy Analysis** - High-entropy string detection for secret and credential discovery
- **MCP Server Deep Validation** - Validates `.mcp.json` configurations for dangerous permissions and untrusted sources
- **Interactive TUI Mode** - Terminal UI for reviewing and triaging findings interactively (`ferret interactive`)
- **Scan Comparison/Diff** - Compare scan results over time to track security posture changes (`ferret diff`)
- **Webhook Notifications** - Send scan results to Slack, Discord, Microsoft Teams, or generic webhooks (`ferret webhook`)
- **Dependency Risk Analysis** - Analyze `package.json` dependencies for known vulnerabilities (`ferret deps`)
- **AI Agent Capability Mapping** - Map and audit AI CLI capability permissions (`ferret capabilities`)
- **Policy Enforcement Mode** - Enforce organizational security policies with configurable rules (`ferret policy`)
- **Inline Ignore Comments** - Support for `ferret-ignore` and `ferret-disable` directives in source files
- **JSON Schema for Config** - Full JSON schema for `.ferretrc.json` with IDE autocompletion support
- **Configurable Exit Codes** - Customizable exit codes for CI/CD pipeline integration
- **CLI Hooks Auto-Scan Guide** - Documentation for using AI CLI hooks to automatically trigger Ferret scans

### Changed
- Enhanced CLI with new command groups: `hooks`, `mcp`, `deps`, `capabilities`, `policy`, `diff`, `interactive`, `webhook`
- Expanded `bin/ferret.js` with all new subcommands

## [1.0.8] - 2026-02-03

### Security
- **ReDoS Vulnerability Remediation** - Replaced greedy `.*` with bounded `[^\n]{0,100}` in regex patterns (CWE-1333)
- **Path Traversal Protection** - Added `pathSecurity.ts` utility with `isPathWithinBase()` and `validatePathWithinBase()` (CWE-22)
- **Arbitrary File Write Prevention** - Added scanned files whitelist, allowed write base restriction, and symlink rejection (CWE-73)
- **JSON Schema Validation** - Added Zod-based validation schemas for all configuration inputs
- **Rate Limiting** - Added `maxMatchesPerPattern`, `maxMatchesPerFile`, `maxExecutionTimeMs` to PatternMatcher
- **Baseline Integrity** - SHA-256 checksum calculation and verification for baseline files
- **HTML Escaping** - Simplified and hardened `escapeHtml()` in HTML reporter
- **Dependency Updates** - Updated eslint to ^9.26.0, @typescript-eslint/* to ^8.54.0, added zod ^3.22.4 (0 npm audit vulnerabilities)

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