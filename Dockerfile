# syntax=docker/dockerfile:1.7
# gisweep production image: multi-stage build with the Playwright Chromium
# binary baked in so `docker run ghcr.io/.../gisweep:latest web https://…`
# works without a follow-up `gisweep install-browsers`.

FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && curl -LsSf https://astral.sh/uv/install.sh | sh \
 && mv /root/.local/bin/uv /usr/local/bin/uv \
 && apt-get purge -y curl \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
RUN uv sync --no-dev --frozen 2>/dev/null \
 || uv sync --no-dev


FROM mcr.microsoft.com/playwright/python:v1.55.0-jammy AS runtime

LABEL org.opencontainers.image.source="https://github.com/enisgetmez/gisweep"
LABEL org.opencontainers.image.description="GIS vulnerability scanner — ArcGIS, OGC, secrets, KVKK/GDPR"
LABEL org.opencontainers.image.licenses="Apache-2.0"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    GISWEEP_IN_DOCKER=1

WORKDIR /app
COPY --from=builder /build/.venv /app/.venv
COPY --from=builder /build/src /app/src
COPY pyproject.toml README.md LICENSE ./

ENV PATH=/app/.venv/bin:$PATH

RUN useradd --create-home --shell /bin/bash gisweep \
 && mkdir -p /home/gisweep/.gisweep \
 && chown -R gisweep:gisweep /app /home/gisweep
USER gisweep

ENTRYPOINT ["gisweep"]
CMD ["--help"]
