# Ferret Language Server (LSP)

Ferret ships with a first-class Language Server (`ferret-lsp`) that brings real-time security analysis directly into your editor.

## Features

- Real-time diagnostics as you type or save
- Hover information with full rule details, severity, and remediation steps
- Intelligent completions (severities, categories, rule IDs)
- Code actions (e.g., "Ignore this finding" with one click)
- Works in any LSP-capable editor

## Installation

### Option 1: Via the main Ferret CLI (recommended)

```bash
ferret lsp
```

### Option 2: Standalone

```bash
npm install -g ferret-lsp
ferret-lsp
```

## Editor Setup

### VS Code

The official Ferret extension supports both **Classic mode** (CLI) and **LSP mode**.

To enable LSP mode:

```json
{
  "ferret.useLanguageServer": true
}
```

You can also specify a custom path:

```json
{
  "ferret.useLanguageServer": true,
  "ferret.languageServerPath": "ferret-lsp"
}
```

A status bar item shows the current mode (`Ferret` vs `Ferret LSP`). Use the command **Ferret: Toggle Language Server Mode** to switch.

### Neovim (with nvim-lspconfig)

```lua
require('lspconfig').ferret_lsp.setup({
  cmd = { "ferret-lsp" },
  filetypes = { "markdown", "json", "yaml", "sh" },
})
```

### Zed

Add to your `settings.json`:

```json
{
  "lsp": {
    "ferret": {
      "command": "ferret-lsp"
    }
  }
}
```

### Emacs (eglot)

```elisp
(add-to-list 'eglot-server-programs
             '((markdown-mode json-mode yaml-mode sh-mode) . ("ferret-lsp")))
```

### Helix

Add to `languages.toml`:

```toml
[[language]]
name = "markdown"
language-server = { command = "ferret-lsp" }
```

## Usage

Once the server is running, open any supported file (`.md`, `.json`, `.yaml`, `.sh`, AI config files like `CLAUDE.md`, `.cursorrules`, etc.).

The server will automatically analyze the file and report security findings.

### Useful Commands (via main Ferret CLI)

```bash
ferret lsp                    # Start the LSP server
ferret scan --self            # Dogfood Ferret on its own source
ferret rules list             # See all available rules
```

## Troubleshooting

**"Failed to start Ferret Language Server"**

- Make sure `ferret-lsp` is installed (`npm install -g ferret-lsp`)
- Try running `ferret-lsp` directly in your terminal to verify it works
- Check that the path in `ferret.languageServerPath` is correct

**No diagnostics appearing**

- Ensure the file type is supported (markdown, json, yaml, shell)
- Try running `ferret check --format json /path/to/your/file` manually
- Check the LSP logs in your editor (most editors have an "Output" panel for LSP)

## Architecture Note

The LSP server is a thin wrapper around Ferret's core scanning engine. It can either:
- Call the installed `ferret` binary (default), or
- Directly import the scanner for faster analysis in development/monorepo setups.

See [architecture.md](./architecture.md) for more details.

## Related

- [Main Ferret Documentation](../README.md)
- [VS Code Extension](../extensions/vscode/README.md)
- [GitHub Repository](https://github.com/fubak/ferret-scan)