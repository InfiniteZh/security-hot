# Multi-stage build: install uv deps in one layer, ship a slim runtime.
FROM python:3.12-slim AS base

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

# Place an empty cache dir; the first fetch fills it.
RUN mkdir -p backend/cache backend/history

EXPOSE 8000

# Drop privileges.
RUN useradd -u 10001 -m -d /home/app app \
    && chown -R app:app /app
USER app

CMD ["uv", "run", "uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
