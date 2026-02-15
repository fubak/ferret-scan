# Ferret Security - VS Code Extension

Real-time security scanning for AI agent configurations.

## Features

- **Real-time Scanning:** Automatically scan files on save
- **Inline Diagnostics:** Security warnings directly in your code
- **Quick Fixes:** One-click remediation for common issues
- **Findings Sidebar:** Browse all security findings in your workspace
- **Configurable:** Control severity levels and scan behavior

## Installation

### From Source

```bash
npm install
npm run compile
```

Then install the extension:
```bash
code --install-extension ferret-security-1.0.0.vsix
```

## Configuration

Add to your VS Code `settings.json`:

```json
{
  "ferret.enabled": true,
  "ferret.scanOnSave": true,
  "ferret.scanOnType": false,
  "ferret.severity": ["CRITICAL", "HIGH", "MEDIUM"],
  "ferret.executablePath": "ferret"
}
```

## Usage

The extension automatically scans supported file types:
- Markdown (.md)
- JSON (.json)
- YAML (.yaml, .yml)
- Shell scripts (.sh, .bash)
- TypeScript/JavaScript (.ts, .js)

Findings appear as:
- Inline squiggly underlines
- Problems panel entries
- Security Findings tree view

## Commands

- `Ferret: Scan Workspace` - Scan all files
- `Ferret: Scan Current File` - Scan active file
- `Ferret: Auto-Fix Issues` - Apply quick fixes
- `Ferret: Show Security Rules` - View rule documentation
- `Ferret: Clear Findings` - Clear all findings

## Requirements

- VS Code 1.85.0 or higher
- ferret-scan CLI installed (`npm install -g ferret-scan`)

## Development

```bash
npm install
npm run watch    # Development mode
npm run compile  # Production build
npm run package  # Create .vsix
```

## License

MIT - See [LICENSE](../../LICENSE)
