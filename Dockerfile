# ── Build stage ──────────────────────────────────────────────────────────
FROM node:22-slim AS node-build
WORKDIR /app
COPY remotion-composer/package*.json ./remotion-composer/
RUN cd remotion-composer && npm ci --omit=dev || npm install

# ── Runtime stage ────────────────────────────────────────────────────────
FROM python:3.11-slim

# System deps: ffmpeg, git, curl, build tools for Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffmpeg \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Python dependencies
COPY requirements.txt requirements-optional.txt ./
RUN pip install --no-cache-dir -r requirements.txt -r requirements-optional.txt

# Copy node_modules from build stage
COPY --from=node-build /app/remotion-composer/node_modules ./remotion-composer/node_modules

# Copy project source
COPY . .

# Create projects directory for Backlot
RUN mkdir -p projects

# Environment defaults
ENV BACKLOT_HOST=0.0.0.0
ENV BACKLOT_PORT=4750
ENV PYTHONUNBUFFERED=1

# Expose Backlot web UI port
EXPOSE 4750

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:4750/api/projects || exit 1

# Run Backlot server — bind to 0.0.0.0 for container access
CMD ["python", "-m", "uvicorn", "backlot.server:app", "--host", "0.0.0.0", "--port", "4750"]
