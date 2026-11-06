# Multi-stage Dockerfile for unified LinkGuard 2.0 deployment

# Stage 1: Build Frontend
FROM node:20-alpine AS frontend-builder
WORKDIR /build
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# Stage 2: Production Python Backend + Static UI
FROM python:3.11-slim
WORKDIR /app

# Install system dependencies (libpcap for scapy if needed, curl for health checks)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r ./backend/requirements.txt

# Copy backend application source
COPY backend/app ./backend/app
COPY backend/scripts ./backend/scripts
COPY backend/tests/fixtures ./backend/tests/fixtures

# Copy built frontend from Stage 1
COPY --from=frontend-builder /build/dist ./frontend/dist

# Environment settings
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

WORKDIR /app/backend

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8000/api/health || exit 1

# Start Uvicorn
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}
