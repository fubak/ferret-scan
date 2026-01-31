# Multi-stage build for Ferret Security Scanner
FROM node:18-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    python3 \
    make \
    g++ \
    git

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY src/ ./src/
COPY bin/ ./bin/

# Build TypeScript
RUN npm run build

# Production stage
FROM node:18-alpine AS production

# Install runtime dependencies
RUN apk add --no-cache \
    dumb-init \
    git \
    curl \
    jq

# Create non-root user for security
RUN addgroup -g 1001 -S ferret && \
    adduser -S ferret -u 1001 -G ferret

# Set working directory
WORKDIR /app

# Copy built application from builder stage
COPY --from=builder --chown=ferret:ferret /app/dist ./dist
COPY --from=builder --chown=ferret:ferret /app/node_modules ./node_modules
COPY --from=builder --chown=ferret:ferret /app/package.json ./

# Copy CLI and make executable
COPY --chown=ferret:ferret bin/ferret.js ./bin/ferret.js
RUN chmod +x ./bin/ferret.js

# Create symlink for global access
RUN ln -s /app/bin/ferret.js /usr/local/bin/ferret

# Create directories for scanning and output
RUN mkdir -p /workspace /output && \
    chown ferret:ferret /workspace /output

# Set security context
USER ferret

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ferret --version || exit 1

# Default entrypoint with dumb-init for proper signal handling
ENTRYPOINT ["/usr/bin/dumb-init", "--", "ferret"]

# Default command shows help
CMD ["--help"]

# Labels for metadata
LABEL org.opencontainers.image.title="Ferret Security Scanner"
LABEL org.opencontainers.image.description="AI-powered security scanner for Claude Code configurations"
LABEL org.opencontainers.image.version="1.0.0"
LABEL org.opencontainers.image.vendor="Ferret Security"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/ferret-security/ferret-scan"
LABEL org.opencontainers.image.documentation="https://github.com/ferret-security/ferret-scan/blob/main/README.md"

# Environment variables for configuration
ENV NODE_ENV=production
ENV LOG_LEVEL=info
ENV FERRET_DATA_DIR=/app/.ferret-data
ENV FERRET_OUTPUT_DIR=/output