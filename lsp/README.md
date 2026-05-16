# Ferret LSP Server

Language Server Protocol implementation for the Ferret security scanner.

Provides real-time security diagnostics, hover information, and completions for AI CLI/agent configuration files across any LSP-capable editor (VS Code, Neovim, Emacs, Zed, Helix, Sublime Text, etc.).

## Installation

```bash
npm install -g ferret-lsp
# or
npx ferret-lsp
```

## Usage

Most editors will launch the server automatically when configured.

### Manual / Testing

```bash
ferret-lsp
# or
node node_modules/ferret-lsp/dist/server.js
```

The server communicates over stdio using the Language Server Protocol.

## Features

- **Diagnostics**: Real-time scanning of `.md`, `.json`, `.yaml`, `.yml`, `.sh` and AI config files (`.claude/`, `.cursor/`, etc.) using Ferret's full rule engine.
- **Hover**: Hover over a finding or rule ID to see description, remediation, severity, and MITRE ATLAS techniques.
- **Completion**: Context-aware completions when editing `.ferretrc.json` or custom rules files (categories, severities, rule IDs).
- **Code Actions**: Quick fixes (where supported).

## Editor Configuration Examples

### Neovim (with nvim-lspconfig)

```lua
require('lspconfig').ferret_lsp.setup {
  cmd = { "ferret-lsp" },
}
```

### Zed

Add to `settings.json`:

```json
{
  "lsp": {
    "ferret": {
      "command": "ferret-lsp"
    }
  }
}
```

### VS Code

The official Ferret VS Code extension can optionally use this LSP server (see extension settings `ferret.useLspServer`).

## Configuration

The LSP server reads your existing `.ferretrc.json` / `.ferretrc` and respects the same settings as the CLI (`thorough`, `semantic-analysis`, `mcp-validation`, etc.).

## Security

The LSP server shells out to the installed `ferret` binary for actual scanning (same isolation model as the VS Code extension). No new network or privilege requirements.

## Development

```bash
cd lsp
npm install
npm run build
npm start
```

## License

MIT
