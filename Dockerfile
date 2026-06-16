# ---------------------------------------------------------------------------
# Dodman · Data Cleaning Proxy — Dockerfile
# ---------------------------------------------------------------------------
# Multi-stage build: keeps the final image lean by separating dependency
# installation from the runtime layer.
#
# Build:  docker build -t dodman-clean-proxy .
# Run:    docker run -p 8000:8000 --env-file .env dodman-clean-proxy
# ---------------------------------------------------------------------------

# ── Stage 1: dependency builder ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# System deps needed to compile asyncpg's C extension
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --prefix=/install --no-cache-dir -r requirements.txt


# ── Stage 2: runtime image ───────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Ensure the runtime base image is up to date for critical OS security patches
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

# Non-root user — never run application code as root
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

# Copy compiled packages from builder
COPY --from=builder /install /usr/local

# Copy application source
COPY main.py .
COPY templates/ templates/

# Render injects PORT at runtime; default to 8000 for local runs
ENV PORT=8000
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Expose the port (documentation only — Render ignores this, uses $PORT)
EXPOSE 8000

# Switch to non-root user
USER appuser

# Uvicorn: single worker per container (Render scales horizontally).
# --proxy-headers trusts X-Forwarded-For from Render's load balancer
# so slowapi's IP-based rate limiting gets the real client IP.
CMD uvicorn main:app \
        --host 0.0.0.0 \
        --port $PORT \
        --proxy-headers \
        --forwarded-allow-ips='*' \
        --workers 1 \
        --log-level info