# Ferret Release Process

This document describes how to cut and publish a new release of Ferret.

## Versioning

We follow [Semantic Versioning](https://semver.org/):

- **Patch** (`x.y.Z`): Bug fixes, small improvements, no breaking changes.
- **Minor** (`x.Y.z`): New features, backward compatible.
- **Major** (`X.y.z`): Breaking changes.

## Release Cadence

Releases are generally cut when there is a meaningful set of changes (new features, important fixes, or when enough time has passed).

## How to Cut a Release

### Recommended Flow (Tag + Automated Release)

1. **Prepare the release**
   - Make sure `main` is up to date and all tests are green.
   - Update `CHANGELOG.md` with a new section for the upcoming version (use the format `## [X.Y.Z] - YYYY-MM-DD`).

2. **Bump versions** (optional but recommended for clarity)
   ```bash
   npm version 2.7.0 --no-git-tag-version          # ferret-scan
   cd lsp && npm version 0.3.0 --no-git-tag-version
   cd ../extensions/vscode && npm version 1.2.0 --no-git-tag-version
   cd ../../
   git add package.json lsp/package.json extensions/vscode/package.json
   git commit -m "chore(release): prepare v2.7.0"
   git push
   ```

3. **Create and push the version tag**
   ```bash
   git tag v2.7.0
   git push origin v2.7.0
   ```

4. **The workflow will automatically**:
   - Run unit tests + E2E tests
   - Publish `ferret-scan` to npm
   - Publish `ferret-lsp` to npm
   - Create a GitHub Release with notes from `CHANGELOG.md`

### Manual Publishing (Emergency / Hotfix)

If you need to publish without cutting a full release:

1. Go to **Actions → "Publish to npm" → "Run workflow"**
2. Fill in the inputs:
   - `version`: e.g. `2.7.0`
   - `skip_tests`: `true` (if tests are already known to pass)
   - `publish_main`: `true`
   - `publish_lsp`: `true`
   - `create_release`: `true` or `false`
   - `dry_run`: `false`

## What Gets Published

| Package          | Directory              | Published To          | Triggered By |
|------------------|------------------------|-----------------------|--------------|
| `ferret-scan`    | Root                   | npm                   | Release / Tag / Manual |
| `ferret-lsp`     | `lsp/`                 | npm                   | Release / Tag / Manual |
| VS Code Extension| `extensions/vscode/`   | VS Code Marketplace   | Manual (`vsce publish`) |

## Post-Release Tasks

After a successful release, consider doing the following:

- [ ] Verify both packages are live on npm
- [ ] Announce the release (Twitter, LinkedIn, Discord, GitHub Discussions)
- [ ] Update any internal documentation or team channels
- [ ] Close the corresponding GitHub milestone (if used)
- [ ] Monitor for any immediate issues reported by users

## Secrets Required

The following repository secrets must be configured:

- `NPM_TOKEN` — NPM token with publish rights (used for both `ferret-scan` and `ferret-lsp`)
- For VS Code extension publishing: A Personal Access Token from the [Visual Studio Marketplace](https://marketplace.visualstudio.com/manage/publishers/ferret-security)

## Tips & Best Practices

- Always update the `CHANGELOG.md` **before** tagging.
- Use `skip_tests: true` only when you are confident the code is good (e.g., re-publishing after a workflow fix).
- `draft_release` now defaults to `true` for both manual runs **and** tag pushes (releases are created as drafts by default for safety — review and publish from the GitHub Releases UI when ready).
- `attach_vscode_extension` defaults to `true` — this automatically builds and attaches the VS Code `.vsix` to the GitHub Release.
- The E2E test job (`test-e2e`) is intentionally non-blocking so that flaky tests do not prevent a release.
- You can publish only one package by setting `publish_main: false` or `publish_lsp: false` during manual dispatch.

## Questions?

If something goes wrong during publishing, check the workflow logs first. Common issues:

- Missing or expired `NPM_TOKEN`
- Test failures in E2E suite (can usually be bypassed with `skip_tests`)
- Version already exists on npm (rare — usually means a tag was pushed twice)

---

Maintained by the Ferret maintainers. Last updated: 2026-05