# Deployment

This guide covers installation, Docker usage, and CI integration for Ferret.

## NPM Installation

```bash
npm install -g ferret-scan
ferret --version
```

Project-local:

```bash
npm install --save-dev ferret-scan
npx ferret-scan scan .
```

## Docker

### Basic Scan

```bash
docker run --rm \
  -v $(pwd):/workspace:ro \
  ghcr.io/fubak/ferret-scan scan /workspace
```

### Report Output

```bash
docker run --rm \
  -v $(pwd):/workspace:ro \
  -v $(pwd)/results:/output:rw \
  ghcr.io/fubak/ferret-scan scan /workspace \
  --format html -o /output/report.html
```

### Docker Compose (Repo)

The repository includes `docker-compose.yml` for local scanning. Typical usage:

```bash
# Basic scan
WORKSPACE_PATH=$(pwd) docker-compose up ferret

# Watch mode
WORKSPACE_PATH=$(pwd) docker-compose --profile watch up ferret-watch
```

If you customize commands, use `scan --watch` for continuous scanning. The repository does not include API or intel update services in Compose profiles.

## CI/CD

### GitHub Actions

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  ferret:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Ferret
        run: npx ferret-scan scan . --ci --format sarif -o results.sarif
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### GitLab CI

```yaml
security_scan:
  stage: test
  image: node:20
  script:
    - npx ferret-scan scan . --ci --format json -o ferret-results.json
  artifacts:
    reports:
      sast: ferret-results.json
```

## Configuration

Place `.ferretrc.json` at the repo root:

```json
{
  "severity": ["critical", "high", "medium"],
  "categories": ["credentials", "injection", "exfiltration"],
  "ignore": ["**/test/**", "**/examples/**"],
  "failOn": "high"
}
```
