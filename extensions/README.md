# Ferret-Scan IDE Extensions

This directory contains IDE integrations for ferret-scan, bringing real-time security scanning directly into your development environment.

## Available Extensions

### VS Code Extension
**Status:** ✅ Complete
**Location:** `vscode/`

Real-time security scanning for AI agent configurations with inline diagnostics and quick fixes.

**Features:**
- Real-time scanning on file save
- Inline diagnostics with severity indicators
- Quick fix code actions
- Security findings tree view
- Configurable severity levels

**Installation:**
```bash
cd vscode
npm install
npm run compile
code --install-extension ferret-security-1.0.0.vsix
```

See `vscode/README.md` for detailed documentation.

## Planned Extensions

### Language Server Protocol (LSP)
**Status:** 🔧 Infrastructure Ready
**Location:** `../lsp/`

Universal IDE support through Language Server Protocol.

**Supported Editors (when complete):**
- Neovim
- Emacs
- Sublime Text
- Atom

### IntelliJ Plugin
**Status:** 🔧 Infrastructure Ready
**Location:** `../plugins/intellij/`

Enterprise-grade support for JetBrains IDEs.

**Target IDEs:**
- IntelliJ IDEA
- WebStorm
- PyCharm
- GoLand

## Development

Each extension has its own build process. See individual README files for details.

## Contributing

Contributions are welcome! See [CONTRIBUTING.md](../CONTRIBUTING.md) for guidelines.
