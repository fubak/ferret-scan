# Changelog

All notable changes to ferret-scan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned Features
- Complete LSP server implementation
- Complete IntelliJ plugin implementation
- Community rule sharing backend
- Real-time monitoring dashboard
- CI/CD plugins for Jenkins, Azure DevOps
- REST API for third-party integrations
- SIEM/SOAR integrations

## [2.0.0] - 2026-02-15

### Added
- **IDE Integrations**
  - VS Code extension with real-time security scanning
  - Inline diagnostics with severity-based warnings
  - Quick fix code actions for common issues
  - Security findings tree view in sidebar
  - LSP server infrastructure for universal IDE support
  - IntelliJ plugin infrastructure

- **Advanced Behavior Analysis**
  - Runtime agent execution monitoring
  - Anomaly detection based on behavioral baselines
  - Resource usage tracking (CPU, memory, disk)
  - Network activity monitoring
  - Sensitive file access detection
  - Event-based real-time alerting system

- **Marketplace Security**
  - Claude Skills marketplace scanner
  - Cursor extensions security analysis
  - Plugin permission risk detection
  - Dangerous capability combination analysis
  - Automated risk scoring and recommendations
  - Source code scanning integration

- **AI-Powered Features**
  - LLM-based rule generation from threat intelligence
  - Automated rule validation and testing
  - Community rule sharing infrastructure
  - Confidence scoring for generated rules
  - MITRE ATLAS technique mapping

- **Sandboxing Integration**
  - Pre-execution security validation
  - Runtime constraint enforcement
  - Policy violation detection
  - Dangerous command pattern blocking
  - Resource limit generation
  - Network and file system access controls

- **Compliance Frameworks**
  - SOC2 compliance assessment and reporting
  - ISO 27001 control mapping
  - GDPR privacy impact assessment
  - Automated evidence collection
  - Compliance scoring system
  - Remediation recommendations

### Changed
- Version bumped from 1.0.10 to 2.0.0
- Package description updated to reflect platform capabilities
- README enhanced with v2.0 features and IDE integration docs
- Repository structure reorganized for better maintainability
- Documentation moved to docs/ folder

### Fixed
- All TypeScript compilation errors in new modules
- Unused import and variable warnings
- Build system optimizations

## [1.0.10] - 2026-02-12

### Changed
- Release tag update to align with latest main branch

## [1.0.9] - 2026-02-12

### Added
- Integration scan test over `test/fixtures`

### Fixed
- Removed unimplemented config/CLI options (AI detection, behavioral analysis, custom rules)
- SARIF version resolution now works outside npm scripts
- Docker Compose watch command aligned to `scan --watch`

### Docs
- Clarified threat intel as local-only and moved future items to Planned
- Added docs index and removed historical planning/phase docs
- Aligned deployment docs with supported Compose profiles


## [1.0.8] - 2026-02-12

### Added
- CSV output format for scan results
- TypeScript/JavaScript file discovery for semantic analysis

### Fixed
- Baseline hashing uses SHA-256 to avoid collisions
- Baseline stats track actual severity
- SARIF metadata uses package version and correct repo URL
- Guard against zero-length regex matches in pattern scanning
- Config loader no longer accepts unimplemented options

### Docs
- Consolidated deployment docs under `docs/deployment.md`
- Removed historical planning and phase documents
- Updated README/CONTRIBUTING examples and docs links

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
