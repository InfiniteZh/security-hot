# Multi-stage build: install uv deps in one layer, ship a slim runtime.
FROM python:3.12-slim AS base

# Build-time proxy passthrough (set HTTP_PROXY / HTTPS_PROXY in your shell or
# docker-compose build args to make apt-get / curl / uv sync go through it).
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
ENV HTTP_PROXY=${HTTP_PROXY} \
    HTTPS_PROXY=${HTTPS_PROXY} \
    http_proxy=${http_proxy} \
    https_proxy=${https_proxy}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_LINK_MODE=copy

# Install uv via pip — more reliable than the curl installer in restricted networks.
RUN pip install --no-cache-dir uv

# gosu: clean privilege-drop from the root entrypoint to the runtime user.
RUN apt-get update \
    && apt-get install -y --no-install-recommends gosu \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy lockfile + manifest first for layer caching.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# Copy application sources.
COPY backend ./backend
COPY scripts ./scripts
COPY web ./web
# Full ~695-feed catalog produced by scripts/merge_rss.py — without this
# the news fetcher silently falls back to the ~26 hardcoded NEWS_SOURCES.
COPY rss/merged.opml ./rss/merged.opml

# Place an empty cache dir; the first fetch fills it.
RUN mkdir -p backend/cache backend/history

EXPOSE 8000

# Create a placeholder 'app' user. Its UID/GID are re-pointed at RUNTIME by the
# entrypoint to match whoever owns the bind-mounted cache dir — so there is no
# build-time APP_UID arg and no host-side `chown` to keep in sync. HOME is fixed
# so uv's cache has a stable, writable location after the entrypoint chowns it.
RUN groupadd -g 1000 app \
    && useradd -u 1000 -g 1000 -m -d /home/app app
ENV HOME=/home/app

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Entrypoint runs as root (resolves UID, fixes ownership), then gosu-drops to the
# runtime user before exec'ing CMD.
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uv", "run", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
