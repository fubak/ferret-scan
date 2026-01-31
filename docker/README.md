# Ferret Docker Deployment

This directory contains Docker configurations for deploying Ferret Security Scanner in various environments.

## Quick Start

### Production Deployment

```bash
# Basic scan
docker-compose up ferret

# Watch mode for continuous monitoring
docker-compose --profile watch up ferret-watch

# API service for integrations
docker-compose --profile api up ferret-api

# Update threat intelligence
docker-compose --profile intel up ferret-intel
```

### Development Environment

```bash
# Start development environment with hot reload
cd docker/
docker-compose -f docker-compose.dev.yml up ferret-dev

# Run tests
docker-compose -f docker-compose.dev.yml --profile test up ferret-test

# Serve documentation
docker-compose -f docker-compose.dev.yml --profile docs up docs-server
```

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# Workspace to scan
WORKSPACE_PATH=/path/to/your/project

# Output directory
OUTPUT_PATH=/path/to/output

# Threat intelligence data
INTEL_PATH=/path/to/intel

# Configuration files
CONFIG_PATH=/path/to/config

# API port (if using API profile)
API_PORT=3000

# Log level
LOG_LEVEL=info
```

### Volume Mounts

- **Workspace** (`/workspace`): Your project directory to scan (read-only)
- **Output** (`/output`): Results and reports directory (read-write)
- **Intel** (`/app/.ferret-intel`): Threat intelligence database (read-write)
- **Config** (`/app/.ferret-config`): Configuration files (read-only)

## Security Features

### Container Security

- **Non-root user**: Runs as user ID 1001
- **Read-only filesystem**: Root filesystem is read-only
- **Dropped capabilities**: All capabilities dropped except essential ones
- **No new privileges**: Prevents privilege escalation
- **Temporary filesystem**: `/tmp` mounted with security restrictions

### Network Security

- **Isolated network**: Custom bridge network for container communication
- **Port restrictions**: Only essential ports exposed
- **Health checks**: Built-in health monitoring

## Service Profiles

### Default Profile
- `ferret`: Basic one-time scan

### Watch Profile
- `ferret-watch`: Continuous file monitoring and scanning

### API Profile
- `ferret-api`: REST API service for integrations

### Intel Profile
- `ferret-intel`: Threat intelligence updater

### Test Profile (Dev)
- `ferret-test`: Test runner with file watching

### Docs Profile (Dev)
- `docs-server`: Documentation server

## Usage Examples

### Scan a Project Directory

```bash
export WORKSPACE_PATH="/path/to/your/claude/project"
export OUTPUT_PATH="./scan-results"

docker-compose up ferret
```

### Continuous Monitoring

```bash
export WORKSPACE_PATH="/path/to/your/claude/project"
export OUTPUT_PATH="./monitoring-results"

docker-compose --profile watch up -d ferret-watch
```

### API Integration

```bash
export WORKSPACE_PATH="/path/to/your/claude/project"
export API_PORT=3000

docker-compose --profile api up -d ferret-api

# API will be available at http://localhost:3000
curl http://localhost:3000/api/scan -X POST -H "Content-Type: application/json" \
  -d '{"path": "/workspace", "format": "json"}'
```

### Update Threat Intelligence

```bash
# Manual update
docker-compose --profile intel up ferret-intel

# Schedule with cron (add to crontab)
0 2 * * * cd /path/to/ferret-scan && docker-compose --profile intel up ferret-intel
```

## Docker Hub Images

Pre-built images are available on Docker Hub:

```bash
# Pull latest stable version
docker pull ferret-security/ferret-scan:latest

# Pull specific version
docker pull ferret-security/ferret-scan:v1.0.0

# Pull development version
docker pull ferret-security/ferret-scan:dev
```

## Building Custom Images

### Build Production Image

```bash
docker build -t ferret-scan:custom .
```

### Build with Custom Base Image

```bash
docker build --build-arg BASE_IMAGE=node:18-slim -t ferret-scan:slim .
```

### Multi-architecture Build

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t ferret-scan:multi .
```

## Troubleshooting

### Common Issues

1. **Permission Errors**: Ensure workspace directory is readable by user ID 1001
2. **Memory Issues**: Increase Docker memory limit for large projects
3. **Network Issues**: Check firewall settings for API profile

### Debug Mode

```bash
# Run with debug logging
LOG_LEVEL=debug docker-compose up ferret

# Access container shell
docker-compose exec ferret sh

# View logs
docker-compose logs ferret
```

### Health Checks

```bash
# Check container health
docker-compose ps

# Manual health check
docker exec ferret-scanner ferret --version
```

## Integration Examples

### CI/CD Pipeline

```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: |
    docker run --rm \
      -v ${{ github.workspace }}:/workspace:ro \
      -v ./results:/output:rw \
      ferret-security/ferret-scan:latest \
      scan /workspace --ci --format sarif -o /output/results.sarif
```

### Kubernetes Deployment

```yaml
# k8s/ferret-scanner.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ferret-scanner
spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: ferret
            image: ferret-security/ferret-scan:latest
            args: ["scan", "/workspace", "--format", "json"]
            volumeMounts:
            - name: workspace
              mountPath: /workspace
              readOnly: true
          volumes:
          - name: workspace
            persistentVolumeClaim:
              claimName: project-workspace
          restartPolicy: OnFailure
```