# syntax=docker/dockerfile:1
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

# System deps needed to compile asyncpg's C extension, plus git so pip
# can clone the private dodman-billing repo below. Builder-stage only -
# the runtime image never gets git, keeping the final image lean.
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libpq-dev \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --upgrade pip \
 && pip install --prefix=/install --no-cache-dir -r requirements.txt

# Internal shared billing package - private repo, installed via a Render
# Secret File (not an ARG/ENV) so the token never lands in an image layer.
# BuildKit's --mount=type=secret only exists for the duration of this one
# RUN instruction; `docker history` on the built image shows nothing.
#
# Setup required in the Render dashboard (one-time, per environment):
#   Service -> Environment -> Secret Files -> Add Secret File
#     Filename: dodman_billing_pat
#     Contents: the raw GitHub fine-grained PAT (read-only, scoped to
#               just the dodman-billing repo) - no KEY=VALUE, just the token
RUN --mount=type=secret,id=dodman_billing_pat,dst=/run/secrets/dodman_billing_pat \
    pip install --prefix=/install --no-cache-dir \
    "git+https://$(cat /run/secrets/dodman_billing_pat)@github.com/dodman-group-hq/dodman-billing.git@main"


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