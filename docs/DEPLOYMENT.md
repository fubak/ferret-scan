# 🚀 Ferret Deployment Guide

Comprehensive guide for deploying Ferret Security Scanner in various environments.

## 📋 Table of Contents

1. [NPM Package Deployment](#npm-package-deployment)
2. [Docker Deployment](#docker-deployment)
3. [CI/CD Integration](#cicd-integration)
4. [Cloud Deployment](#cloud-deployment)
5. [Enterprise Deployment](#enterprise-deployment)
6. [Monitoring & Maintenance](#monitoring--maintenance)

## 📦 NPM Package Deployment

### Global Installation

```bash
# Install globally for system-wide access
npm install -g ferret-scan

# Verify installation
ferret --version
```

### Project-Local Installation

```bash
# Install as development dependency
npm install --save-dev ferret-scan

# Add to package.json scripts
{
  "scripts": {
    "security:scan": "ferret scan .",
    "security:watch": "ferret watch .",
    "security:report": "ferret scan . --format html -o security-report.html"
  }
}
```

### Package Registry Configuration

For private registries:

```bash
# Configure npm registry
npm config set registry https://your-private-registry.com/

# Install from private registry
npm install -g @your-org/ferret-scan
```

## 🐳 Docker Deployment

### Quick Start

```bash
# Pull official image
docker pull ferret-security/ferret-scan:latest

# Basic scan
docker run --rm \
  -v $(pwd):/workspace:ro \
  -v ./results:/output:rw \
  ferret-security/ferret-scan \
  scan /workspace --format json -o /output/results.json
```

### Production Docker Compose

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  ferret-scanner:
    image: ferret-security/ferret-scan:latest
    container_name: ferret-prod
    restart: unless-stopped
    environment:
      - NODE_ENV=production
      - LOG_LEVEL=info
    volumes:
      - ${WORKSPACE_PATH}:/workspace:ro
      - ${OUTPUT_PATH}:/output:rw
      - ${INTEL_PATH}:/app/.ferret-intel:rw
    networks:
      - ferret-network
    security_opt:
      - no-new-privileges:true
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    user: "1001:1001"
    cap_drop:
      - ALL

  # Scheduled scanning
  ferret-cron:
    image: ferret-security/ferret-scan:latest
    container_name: ferret-cron
    restart: unless-stopped
    environment:
      - CRON_SCHEDULE=0 2 * * *  # Daily at 2 AM
    volumes:
      - ${WORKSPACE_PATH}:/workspace:ro
      - ${OUTPUT_PATH}:/output:rw
    command: |
      sh -c '
        echo "$CRON_SCHEDULE ferret scan /workspace --format json -o /output/daily-\$(date +%Y%m%d).json" | crontab -
        crond -f
      '
    networks:
      - ferret-network

networks:
  ferret-network:
    driver: bridge
```

### Docker Swarm Deployment

```yaml
# docker-compose.swarm.yml
version: '3.8'

services:
  ferret:
    image: ferret-security/ferret-scan:latest
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      update_config:
        parallelism: 1
        delay: 30s
      placement:
        constraints:
          - node.role == worker
    networks:
      - ferret-overlay
    volumes:
      - ferret-data:/app/.ferret-data
    configs:
      - source: ferret-config
        target: /app/ferret.config.json

networks:
  ferret-overlay:
    driver: overlay
    attachable: true

volumes:
  ferret-data:
    driver: local

configs:
  ferret-config:
    file: ./ferret.config.json
```

## 🔄 CI/CD Integration

### GitHub Actions

#### Basic Security Scan

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      actions: read
      contents: read
      security-events: write

    steps:
    - name: Checkout code
      uses: actions/checkout@v4

    - name: Setup Node.js
      uses: actions/setup-node@v4
      with:
        node-version: '18'
        cache: 'npm'

    - name: Install Ferret
      run: npm install -g ferret-scan@latest

    - name: Run security scan
      run: |
        ferret scan . \
          --ci \
          --format sarif \
          --output results.sarif

    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v3
      with:
        sarif_file: results.sarif
        category: ferret-scan

    - name: Upload scan results
      uses: actions/upload-artifact@v4
      with:
        name: security-scan-results
        path: results.sarif
        retention-days: 30
```

#### Multi-Environment Scan

```yaml
# .github/workflows/multi-env-security.yml
name: Multi-Environment Security

on: [push, pull_request]

jobs:
  scan-matrix:
    strategy:
      matrix:
        environment: [development, staging, production]
        format: [sarif, json, html]

    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v4

    - name: Configure environment
      run: |
        case "${{ matrix.environment }}" in
          development)
            echo "SCAN_ARGS=--dev --verbose" >> $GITHUB_ENV
            ;;
          staging)
            echo "SCAN_ARGS=--severity medium" >> $GITHUB_ENV
            ;;
          production)
            echo "SCAN_ARGS=--severity high --strict" >> $GITHUB_ENV
            ;;
        esac

    - name: Run scan
      run: |
        npx ferret-scan $SCAN_ARGS \
          --format ${{ matrix.format }} \
          --output results-${{ matrix.environment }}.${{ matrix.format }}
```

### Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any

    environment {
        FERRET_VERSION = 'latest'
        WORKSPACE_PATH = "${WORKSPACE}"
        OUTPUT_PATH = "${WORKSPACE}/security-results"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }

        stage('Install Ferret') {
            steps {
                sh 'npm install -g ferret-scan@${FERRET_VERSION}'
            }
        }

        stage('Security Scan') {
            parallel {
                stage('Quick Scan') {
                    steps {
                        sh '''
                            mkdir -p ${OUTPUT_PATH}
                            ferret scan ${WORKSPACE_PATH} \
                                --format json \
                                --output ${OUTPUT_PATH}/quick-scan.json
                        '''
                    }
                }

                stage('Deep Scan') {
                    steps {
                        sh '''
                            ferret scan ${WORKSPACE_PATH} \
                                --deep --semantic --correlate \
                                --format html \
                                --output ${OUTPUT_PATH}/deep-scan.html
                        '''
                    }
                }
            }
        }

        stage('Process Results') {
            steps {
                script {
                    def results = readJSON file: "${OUTPUT_PATH}/quick-scan.json"
                    def criticalCount = results.findings.count { it.severity == 'CRITICAL' }

                    if (criticalCount > 0) {
                        currentBuild.result = 'FAILURE'
                        error("Found ${criticalCount} critical security issues!")
                    }
                }
            }
        }

        stage('Archive Results') {
            steps {
                archiveArtifacts artifacts: 'security-results/**', fingerprint: true
                publishHTML([
                    allowMissing: false,
                    alwaysLinkToLastBuild: true,
                    keepAll: true,
                    reportDir: 'security-results',
                    reportFiles: '*.html',
                    reportName: 'Security Scan Report'
                ])
            }
        }
    }

    post {
        always {
            cleanWs()
        }
        failure {
            emailext (
                subject: "Security Scan Failed: ${env.JOB_NAME} - ${env.BUILD_NUMBER}",
                body: "Critical security issues found in build ${env.BUILD_NUMBER}",
                to: "${env.SECURITY_TEAM_EMAIL}"
            )
        }
    }
}
```

### GitLab CI

```yaml
# .gitlab-ci.yml
variables:
  FERRET_VERSION: "latest"
  OUTPUT_DIR: "security-results"

stages:
  - security
  - report
  - deploy

security_scan:
  stage: security
  image: node:18-alpine
  before_script:
    - npm install -g ferret-scan@$FERRET_VERSION
    - mkdir -p $OUTPUT_DIR
  script:
    - ferret scan . --ci --format json --output $OUTPUT_DIR/results.json
    - ferret scan . --ci --format sarif --output $OUTPUT_DIR/results.sarif
  artifacts:
    reports:
      sast: $OUTPUT_DIR/results.sarif
    paths:
      - $OUTPUT_DIR/
    expire_in: 1 week
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

security_report:
  stage: report
  image: node:18-alpine
  dependencies:
    - security_scan
  script:
    - npx ferret-scan --format html --input $OUTPUT_DIR/results.json --output $OUTPUT_DIR/report.html
  artifacts:
    paths:
      - $OUTPUT_DIR/report.html
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

deploy_security_dashboard:
  stage: deploy
  image: alpine:latest
  dependencies:
    - security_report
  script:
    - apk add --no-cache rsync openssh
    - rsync -av $OUTPUT_DIR/ $DASHBOARD_SERVER:/var/www/security/
  environment:
    name: security-dashboard
    url: https://security-dashboard.example.com
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
```

## ☁️ Cloud Deployment

### AWS

#### ECS Deployment

```json
{
  "family": "ferret-scanner",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ferretTaskRole",
  "containerDefinitions": [
    {
      "name": "ferret-scanner",
      "image": "ferret-security/ferret-scan:latest",
      "essential": true,
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/ferret-scanner",
          "awslogs-region": "us-west-2",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "FERRET_API_KEY",
          "valueFrom": "/ferret/api-key"
        }
      ],
      "mountPoints": [
        {
          "sourceVolume": "workspace",
          "containerPath": "/workspace",
          "readOnly": true
        }
      ]
    }
  ],
  "volumes": [
    {
      "name": "workspace",
      "efsVolumeConfiguration": {
        "fileSystemId": "fs-12345678",
        "transitEncryption": "ENABLED"
      }
    }
  ]
}
```

#### Lambda Deployment

```yaml
# serverless.yml
service: ferret-scanner

provider:
  name: aws
  runtime: nodejs18.x
  stage: ${opt:stage, 'dev'}
  region: us-west-2
  timeout: 300
  memorySize: 1024

functions:
  scanner:
    handler: lambda/scanner.handler
    events:
      - schedule: rate(1 hour)
      - http:
          path: /scan
          method: post
    environment:
      FERRET_S3_BUCKET: ${self:custom.bucketName}
    layers:
      - arn:aws:lambda:us-west-2:123456789:layer:ferret-scanner:1

resources:
  Resources:
    FerretBucket:
      Type: AWS::S3::Bucket
      Properties:
        BucketName: ${self:custom.bucketName}
        VersioningConfiguration:
          Status: Enabled
        PublicAccessBlockConfiguration:
          BlockPublicAcls: true
          BlockPublicPolicy: true
          IgnorePublicAcls: true
          RestrictPublicBuckets: true

custom:
  bucketName: ferret-scanner-${self:provider.stage}
```

### Google Cloud Platform

#### Cloud Run Deployment

```yaml
# cloud-run.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: ferret-scanner
  annotations:
    run.googleapis.com/ingress: internal-and-cloud-load-balancing
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/maxScale: "5"
        autoscaling.knative.dev/minScale: "1"
        run.googleapis.com/cpu-throttling: "false"
        run.googleapis.com/execution-environment: gen2
    spec:
      serviceAccountName: ferret-scanner@PROJECT-ID.iam.gserviceaccount.com
      containerConcurrency: 10
      containers:
      - image: gcr.io/PROJECT-ID/ferret-scanner:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: GCP_PROJECT
          value: "PROJECT-ID"
        resources:
          limits:
            cpu: "1"
            memory: "1Gi"
        volumeMounts:
        - name: workspace
          mountPath: /workspace
      volumes:
      - name: workspace
        secret:
          secretName: ferret-workspace-config
```

### Azure

#### Container Instances

```yaml
# azure-container-instance.yml
apiVersion: 2019-12-01
location: eastus
name: ferret-scanner
properties:
  containers:
  - name: ferret
    properties:
      image: ferret-security/ferret-scan:latest
      resources:
        requests:
          cpu: 1
          memoryInGb: 1
      environmentVariables:
      - name: NODE_ENV
        value: production
      - name: AZURE_STORAGE_ACCOUNT
        secureValue: storageAccountName
      volumeMounts:
      - name: workspace
        mountPath: /workspace
  osType: Linux
  restartPolicy: Always
  volumes:
  - name: workspace
    azureFile:
      shareName: workspace
      storageAccountName: mystorageaccount
      storageAccountKey: storagekey
tags:
  Environment: production
  Service: ferret-scanner
```

## 🏢 Enterprise Deployment

### Kubernetes

#### Production Deployment

```yaml
# k8s/namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: ferret-security
  labels:
    name: ferret-security

---
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ferret-config
  namespace: ferret-security
data:
  ferret.config.json: |
    {
      "scan": {
        "include": [".claude/**", "skills/**"],
        "exclude": ["node_modules", "dist"],
        "maxFileSize": "10MB"
      },
      "rules": {
        "severity": "medium",
        "categories": ["credentials", "injection"]
      },
      "output": {
        "format": "json",
        "verbose": false
      }
    }

---
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: ferret-secrets
  namespace: ferret-security
type: Opaque
data:
  api-key: <base64-encoded-api-key>
  intel-key: <base64-encoded-intel-key>

---
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ferret-scanner
  namespace: ferret-security
  labels:
    app: ferret-scanner
spec:
  replicas: 3
  selector:
    matchLabels:
      app: ferret-scanner
  template:
    metadata:
      labels:
        app: ferret-scanner
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1001
        fsGroup: 1001
      containers:
      - name: ferret
        image: ferret-security/ferret-scan:latest
        imagePullPolicy: Always
        ports:
        - containerPort: 3000
          name: api
        env:
        - name: NODE_ENV
          value: "production"
        - name: API_ENABLED
          value: "true"
        envFrom:
        - secretRef:
            name: ferret-secrets
        resources:
          requests:
            cpu: 500m
            memory: 512Mi
          limits:
            cpu: 1
            memory: 1Gi
        volumeMounts:
        - name: config
          mountPath: /app/ferret.config.json
          subPath: ferret.config.json
        - name: workspace
          mountPath: /workspace
          readOnly: true
        - name: output
          mountPath: /output
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: config
        configMap:
          name: ferret-config
      - name: workspace
        persistentVolumeClaim:
          claimName: ferret-workspace-pvc
      - name: output
        persistentVolumeClaim:
          claimName: ferret-output-pvc

---
# k8s/service.yaml
apiVersion: v1
kind: Service
metadata:
  name: ferret-service
  namespace: ferret-security
spec:
  selector:
    app: ferret-scanner
  ports:
  - name: api
    port: 80
    targetPort: 3000
  type: ClusterIP

---
# k8s/cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ferret-scheduled-scan
  namespace: ferret-security
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: ferret
            image: ferret-security/ferret-scan:latest
            command:
            - ferret
            - scan
            - /workspace
            - --format
            - json
            - --output
            - /output/scheduled-scan.json
            volumeMounts:
            - name: workspace
              mountPath: /workspace
              readOnly: true
            - name: output
              mountPath: /output
          volumes:
          - name: workspace
            persistentVolumeClaim:
              claimName: ferret-workspace-pvc
          - name: output
            persistentVolumeClaim:
              claimName: ferret-output-pvc
          restartPolicy: OnFailure
```

#### Helm Chart

```yaml
# helm/ferret-scanner/Chart.yaml
apiVersion: v2
name: ferret-scanner
description: AI-powered security scanner for Claude Code configurations
type: application
version: 1.0.0
appVersion: "1.0.0"
keywords:
  - security
  - scanner
  - ai-security
maintainers:
  - name: Ferret Security Team
    email: security@ferret-scan.dev

---
# helm/ferret-scanner/values.yaml
replicaCount: 3

image:
  repository: ferret-security/ferret-scan
  tag: "latest"
  pullPolicy: Always

service:
  type: ClusterIP
  port: 80
  targetPort: 3000

ingress:
  enabled: true
  className: "nginx"
  annotations:
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
  hosts:
    - host: ferret.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: ferret-tls
      hosts:
        - ferret.example.com

persistence:
  enabled: true
  storageClass: "fast-ssd"
  size: 10Gi

resources:
  limits:
    cpu: 1
    memory: 1Gi
  requests:
    cpu: 500m
    memory: 512Mi

autoscaling:
  enabled: true
  minReplicas: 2
  maxReplicas: 10
  targetCPUUtilizationPercentage: 70

securityContext:
  runAsNonRoot: true
  runAsUser: 1001
  fsGroup: 1001

cronjob:
  enabled: true
  schedule: "0 2 * * *"
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 1
```

## 📊 Monitoring & Maintenance

### Health Monitoring

```yaml
# docker-compose.monitoring.yml
version: '3.8'

services:
  prometheus:
    image: prom/prometheus:latest
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
      - '--web.console.libraries=/etc/prometheus/console_libraries'
      - '--web.console.templates=/etc/prometheus/consoles'

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3001:3000"
    environment:
      - GF_SECURITY_ADMIN_PASSWORD=admin
    volumes:
      - grafana-storage:/var/lib/grafana
      - ./grafana/dashboards:/var/lib/grafana/dashboards

  ferret-exporter:
    image: ferret-security/ferret-scan:latest
    command: ["metrics-exporter", "--port", "9100"]
    ports:
      - "9100:9100"
    depends_on:
      - prometheus

volumes:
  grafana-storage:
```

### Log Management

```yaml
# docker-compose.logging.yml
version: '3.8'

services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:7.15.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"

  kibana:
    image: docker.elastic.co/kibana/kibana:7.15.0
    ports:
      - "5601:5601"
    depends_on:
      - elasticsearch

  logstash:
    image: docker.elastic.co/logstash/logstash:7.15.0
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    depends_on:
      - elasticsearch

  ferret-scanner:
    image: ferret-security/ferret-scan:latest
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
    environment:
      - LOG_FORMAT=json
      - LOG_LEVEL=info
```

### Backup Strategy

```bash
#!/bin/bash
# backup.sh - Backup ferret data and configurations

BACKUP_DIR="/backup/ferret"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="${BACKUP_DIR}/ferret_backup_${DATE}.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Backup configurations and data
tar -czf "$BACKUP_FILE" \
    /app/.ferret-config \
    /app/.ferret-intel \
    /output \
    /app/ferret.config.json

# Keep only last 7 days of backups
find "$BACKUP_DIR" -name "ferret_backup_*.tar.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_FILE"
```

### Maintenance Scripts

```bash
#!/bin/bash
# maintenance.sh - Regular maintenance tasks

# Update threat intelligence
ferret intel update --force

# Clean old scan results
find /output -name "*.json" -mtime +30 -delete

# Vacuum quarantine database
ferret fix vacuum

# Check system health
ferret health --detailed

# Rotate logs
logrotate /etc/logrotate.d/ferret

echo "Maintenance completed at $(date)"
```

## 🔧 Configuration Management

### Environment-Specific Configs

```javascript
// config/production.js
module.exports = {
  scan: {
    maxFileSize: "50MB",
    maxConcurrency: 8,
    timeout: "30m"
  },
  intelligence: {
    updateInterval: "6h",
    retries: 3
  },
  logging: {
    level: "info",
    format: "json",
    destination: "/var/log/ferret/app.log"
  },
  api: {
    port: 3000,
    host: "0.0.0.0",
    rateLimit: {
      windowMs: 900000, // 15 minutes
      max: 100 // requests per windowMs
    }
  }
};
```

### Secrets Management

```bash
# Using HashiCorp Vault
vault kv put secret/ferret \
  api_key="your-api-key" \
  intel_key="your-intel-key" \
  db_password="your-db-password"

# Using Kubernetes Secrets
kubectl create secret generic ferret-secrets \
  --from-literal=api-key=your-api-key \
  --from-literal=intel-key=your-intel-key

# Using Docker Secrets
echo "your-api-key" | docker secret create ferret_api_key -
echo "your-intel-key" | docker secret create ferret_intel_key -
```

This comprehensive deployment guide covers all major deployment scenarios for Ferret Security Scanner. Choose the approach that best fits your infrastructure and requirements.