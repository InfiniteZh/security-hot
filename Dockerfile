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

# Install uv (fast Python package manager).
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && curl -LsSf https://astral.sh/uv/install.sh | sh \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/root/.local/bin:${PATH}"

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

# Drop privileges. UID/GID are build args so bind-mounted host dirs
# (backend/cache, backend/history) can match the deploy user — avoids
# "unable to open database file" from SQLite when the container user
# can't write the mount point.
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd -g ${APP_GID} app \
    && useradd -u ${APP_UID} -g ${APP_GID} -m -d /home/app app \
    && chown -R app:app /app
USER app

CMD ["uv", "run", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
