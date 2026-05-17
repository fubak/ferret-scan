# Publishing Ferret

This document describes how to publish new versions of Ferret and its companion packages.

## Packages

Ferret maintains two npm packages:

| Package       | Directory | Description                          | Auto-published? |
|---------------|-----------|--------------------------------------|-----------------|
| `ferret-scan` | `/`       | Main CLI tool                        | Yes (on release) |
| `ferret-lsp`  | `/lsp`    | Language Server for editors          | Yes (on release) |

The VS Code extension is published separately via `vsce`.

## Automated Publishing (Recommended)

Publishing is triggered automatically when you create a new GitHub Release.

### Steps

1. **Ensure everything is ready**
   - All tests pass (`npm test`)
   - Self-scan passes (`ferret scan --self --ci`)
   - Documentation is up to date
   - `CHANGELOG.md` has an entry for the new version

2. **Update versions**
   ```bash
   npm version 2.7.0 --no-git-tag-version
   cd lsp && npm version 0.3.0 --no-git-tag-version
   cd ../extensions/vscode && npm version 1.2.0 --no-git-tag-version
   ```

3. **Commit and push the version bumps**
   ```bash
   git add package.json lsp/package.json extensions/vscode/package.json
   git commit -m "chore(release): bump versions for v2.7.0"
   git push
   ```

4. **Create a GitHub Release**
   - Go to **Releases → Draft a new release**
   - Create a new tag (e.g., `v2.7.0`)
   - Use the title `Ferret v2.7.0`
   - Paste the relevant section from `CHANGELOG.md` into the release notes
   - Publish the release

5. **Wait for the workflow**
   - The `Publish to npm` workflow will run automatically.
   - It will publish both `ferret-scan` and `ferret-lsp`.

## Manual Publishing

If you need to publish outside of the release flow:

### Publish `ferret-scan`

```bash
npm ci
npm run build
npm test

# Dry run first
npm publish --dry-run

# Actual publish
npm publish --access public --provenance
```

### Publish `ferret-lsp`

```bash
cd lsp

npm ci
npm run build

# Dry run
npm publish --dry-run

# Publish
npm publish --access public
```

### Publish VS Code Extension

```bash
cd extensions/vscode

npm install
npm run compile

# Package locally (for testing)
npx @vscode/vsce package

# Publish to Visual Studio Marketplace
npx @vscode/vsce publish

# Optional: Publish to Open VSX Registry
npx ovsx publish
```

## Required Secrets

The following repository secrets must be configured:

- `NPM_TOKEN` — NPM access token with publish rights for both packages.
- For the VS Code extension: Personal Access Token from the [VS Code Marketplace](https://marketplace.visualstudio.com/manage).

## Versioning Rules

- Follow [Semantic Versioning](https://semver.org/).
- Use `npm version <type>` (patch, minor, major) when possible.
- Always update the version in:
  - `package.json` (root)
  - `lsp/package.json`
  - `extensions/vscode/package.json`

## Post-Release Tasks

After publishing:

- [ ] Announce on Twitter / LinkedIn / Discord
- [ ] Update any internal documentation
- [ ] Close the GitHub milestone (if used)
- [ ] Celebrate 🎉

## Troubleshooting

**"You do not have permission to publish"**
- Make sure you're using the correct NPM token with `publish` scope.

**"Package name too similar to existing package"**
- `ferret-lsp` and `ferret-scan` are intentionally separate. Make sure you're in the correct directory.

**Workflow didn't trigger**
- Confirm the release was created as a **published** release (not a draft or pre-release, unless configured otherwise).