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

### Language Server Mode (Recommended)

Ferret includes a full **Language Server** (`ferret-lsp`) for the best editor experience:

- Real-time diagnostics
- Hover with detailed rule information and remediation steps
- Intelligent completions (rule IDs, severities, categories)
- Code actions (e.g., "Ignore this finding" with one click)

#### Enable LSP Mode

```json
{
  "ferret.useLanguageServer": true
}
```

#### Requirements

1. Install the language server:
   ```bash
   npm install -g ferret-lsp
   ```

2. (Optional) Specify a custom path:
   ```json
   {
     "ferret.languageServerPath": "/path/to/ferret-lsp"
   }
   ```

#### Features

- A status bar item shows whether you are in **Classic** or **LSP** mode.
- Use **Ferret: Toggle Language Server Mode** to switch instantly.
- If `ferret-lsp` cannot be found, the extension will show a helpful error and offer to fall back to Classic mode.

> **Tip**: LSP mode is strongly recommended for Neovim, Zed, and other editors, and provides a significantly better experience even in VS Code.

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
