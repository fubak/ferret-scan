# Architecture

Ferret is a CLI security scanner for AI assistant configuration files. The scanner focuses on known AI CLI formats (Claude Code, Cursor, Windsurf, Continue, Aider, Cline) and generic AI configs.

## Core Components

- **CLI** (`bin/ferret.js`): argument parsing, config loading, scan orchestration, reporting, and exit codes.
- **Config & Ignore** (`src/utils/config.ts`, `src/utils/ignore.ts`): merges CLI options with `.ferretrc` and `.ferretignore`.
- **File Discovery** (`src/scanner/FileDiscovery.ts`): finds relevant config, markdown, JSON, YAML, and shell files.
- **Rule Engine** (`src/scanner/PatternMatcher.ts`, `src/rules/*`): regex-based matching with context filters and severity.
- **Semantic Analysis** (`src/analyzers/AstAnalyzer.ts`): AST-based checks for JS/TS and code blocks in markdown.
- **Correlation Analysis** (`src/analyzers/CorrelationAnalyzer.ts`): cross-file pattern correlation.
- **Threat Intelligence** (`src/intelligence/*`): indicator matching against a local threat database (no external feeds by default).
- **Remediation** (`src/remediation/*`): safe auto-fix and quarantine helpers.
- **Reporters** (`src/reporters/*`): console, JSON, SARIF, HTML, and CSV outputs.

## Data Flow (Scan)

1. CLI loads config and resolves scan paths.
2. File discovery collects analyzable files and applies ignore rules.
3. Pattern matching runs across files and rules.
4. Optional semantic and correlation analyses run if enabled.
5. Optional threat intel matching runs if enabled (local indicator set).
6. Findings are sorted, summarized, and reported.
7. Exit code is determined by severity threshold.

## Files Analyzed

Ferret focuses on AI CLI configs plus related scripts:

- `CLAUDE.md`, `.mcp.json`, `.claude/`, `settings.json`
- `.cursorrules`, `.cursor/`
- `.windsurfrules`, `.windsurf/`
- `.continue/`
- `.aider/`, `.aider.conf.yml`, `.aiderignore`
- `.cline/`, `.clinerules`
- `.ai/`, `AI.md`, `AGENT.md`, `AGENTS.md`
- Markdown, JSON, YAML, and shell scripts in these trees

## Outputs

- `console`: human-friendly terminal output
- `json`: machine-readable
- `sarif`: GitHub code scanning integration
- `html`: standalone report
- `csv`: flat export for spreadsheets

## Extensibility

- Add new rules in `src/rules/`.
- Use `.ferretrc.json` for default settings and ignore patterns.
- Use `ferret rules` and `ferret baseline` to manage rules and accepted findings.
