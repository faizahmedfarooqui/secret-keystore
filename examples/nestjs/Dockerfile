# ============================================================================
# NestJS Secret Keystore Example - Dockerfile
# ============================================================================
# Multi-stage build for production-ready container
# ============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Install dependencies
# -----------------------------------------------------------------------------
FROM node:20-alpine AS deps

WORKDIR /app

# Enable pnpm via corepack
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate

# Copy package files
COPY package.json pnpm-lock.yaml ./

# Install production dependencies only
RUN pnpm install --frozen-lockfile --prod && pnpm store prune

# -----------------------------------------------------------------------------
# Stage 2: Build application
# -----------------------------------------------------------------------------
FROM node:20-alpine AS builder

WORKDIR /app

# Enable pnpm via corepack
RUN corepack enable && corepack prepare pnpm@9.15.9 --activate

# Copy package files and install all dependencies (including dev)
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

# Copy source code
COPY . .

# Build the NestJS application
RUN pnpm run build

# -----------------------------------------------------------------------------
# Stage 3: Production image
# -----------------------------------------------------------------------------
FROM node:20-alpine AS runner

# Security: Run as non-root user
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nestjs

WORKDIR /app

# Set production environment
ENV NODE_ENV=production
ENV PORT=3000

# Copy production dependencies from deps stage
COPY --from=deps /app/node_modules ./node_modules

# Copy built application from builder stage
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package*.json ./

# Copy .env file (should contain encrypted values)
# NOTE: In production, mount this as a secret or use environment variables
COPY .env .env

# Set ownership
RUN chown -R nestjs:nodejs /app

# Switch to non-root user
USER nestjs

# Expose application port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

# Start the application
CMD ["node", "dist/main.js"]
