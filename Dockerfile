# Multi-stage build for Ferret Security Scanner
FROM node:20-alpine AS builder

# Install build dependencies
RUN apk add --no-cache python3 make g++

WORKDIR /app

# Copy package files and install all dependencies (including devDependencies for build)
COPY package*.json ./
RUN npm ci

# Copy source and build
COPY tsconfig.json ./
COPY src/ ./src/
COPY bin/ ./bin/
RUN npm run build

# Production stage
FROM node:20-alpine

RUN apk add --no-cache dumb-init git

# Create non-root user
RUN addgroup -g 1001 -S ferret && \
    adduser -S ferret -u 1001 -G ferret

WORKDIR /app

# Copy only production dependencies
COPY package*.json ./
RUN npm ci --omit=dev --ignore-scripts

# Copy built application from builder stage
COPY --from=builder --chown=ferret:ferret /app/dist ./dist
COPY --chown=ferret:ferret bin/ferret.js ./bin/ferret.js
COPY --chown=ferret:ferret src/rules/ ./src/rules/
RUN chmod +x ./bin/ferret.js && \
    ln -s /app/bin/ferret.js /usr/local/bin/ferret

# Create directories for scanning and output
RUN mkdir -p /workspace /output && \
    chown ferret:ferret /workspace /output

USER ferret

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ferret --version || exit 1

ENTRYPOINT ["/usr/bin/dumb-init", "--", "ferret"]
CMD ["--help"]

LABEL org.opencontainers.image.title="Ferret Security Scanner"
LABEL org.opencontainers.image.description="Security scanner for AI CLI configurations"
LABEL org.opencontainers.image.version="2.1.0"
LABEL org.opencontainers.image.vendor="Ferret Security"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/fubak/ferret-scan"

ENV NODE_ENV=production
ENV NO_COLOR=
