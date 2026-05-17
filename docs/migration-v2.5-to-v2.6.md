# Migration Guide: v2.5 → v2.6

This guide helps existing users upgrade from Ferret v2.5.0 to v2.6.0.

## Breaking Changes

**None.** v2.6.0 is fully backward compatible with v2.5.0. All existing commands, configuration files, and behavior remain the same unless you opt into the new features.

## New Features Overview

### 1. Language Server Protocol (LSP)

You can now run a full LSP server:

```bash
ferret lsp
```

This enables real-time diagnostics, hover, completions, and code actions in editors.

**VS Code users**: Enable it with:

```json
{ "ferret.useLanguageServer": true }
```

See the [LSP Guide](./lsp.md) for editor-specific setup.

### 2. SBOM + AIBOM Generation

New output formats for supply chain and AI security compliance:

```bash
ferret scan . --format sbom          # CycloneDX 1.5
ferret scan . --format aibom         # AI-extended BOM
ferret scan . --sbom --sbom-format aibom
```

### 3. Runtime Prompt Monitoring

New command for real-time analysis during LLM CLI usage:

```bash
ferret monitor --stdio                    # Pipe mode
ferret monitor --target claude            # Wrapper mode
echo "Ignore previous instructions..." | ferret monitor --stdio --block
```

By default it alerts only. Use `--block` to prevent high-risk prompts from reaching the LLM.

### 4. Community Rule Sharing

Load rules from GitHub with a simple shorthand:

```bash
ferret rules fetch github:your-org/ferret-rules/rules/injection.yml
ferret rules install github:your-org/ferret-rules
ferret rules validate github:your-org/ferret-rules
```

Rules are validated for safety (no ReDoS, no shadowing of built-in rule IDs).

## Recommended Upgrade Steps

1. **Update Ferret**
   ```bash
   npm install -g ferret-scan@latest
   ```

2. **(Optional but recommended)** Install the Language Server
   ```bash
   npm install -g ferret-lsp
   ```

3. **Test the new features**
   ```bash
   ferret scan --self --ci                    # Verify self-scan still works
   ferret lsp                                  # Try the LSP server
   ferret monitor --stdio --help             # Explore runtime monitoring
   ```

4. **Update your VS Code settings** (if desired)
   ```json
   {
     "ferret.useLanguageServer": true
   }
   ```

## Configuration Changes

No existing settings were removed or changed in behavior. New settings were added:

- `ferret.useLanguageServer`
- `ferret.languageServerPath`

## Getting Help

- [LSP Documentation](./lsp.md)
- [Main README](../README.md)
- [GitHub Discussions](https://github.com/fubak/ferret-scan/discussions)
- [Report an issue](https://github.com/fubak/ferret-scan/issues)

Welcome to Ferret v2.6.0!