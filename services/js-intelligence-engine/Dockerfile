# JS Intelligence Engine — Dockerfile
# Lighter than runtime-analysis-engine: no Playwright/Chromium needed
FROM python:3.12-slim

WORKDIR /app

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv==0.5.14

# Copy workspace libs first for layer caching
COPY libs/db-base ./libs/db-base
COPY libs/event-schemas ./libs/event-schemas
COPY libs/kafka-client ./libs/kafka-client
COPY libs/observability ./libs/observability
COPY libs/security ./libs/security

# Copy service
COPY services/js-intelligence-engine ./services/js-intelligence-engine

# Install all dependencies (tree-sitter wheels are pre-built; no compilation needed)
RUN uv pip install --system --no-cache \
    -e ./libs/db-base \
    -e ./libs/event-schemas \
    -e ./libs/kafka-client \
    -e ./libs/observability \
    -e ./libs/security \
    -e ./services/js-intelligence-engine

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8005

RUN addgroup --system --gid 1001 cves \
    && adduser --system --uid 1001 --gid 1001 --no-create-home cves \
    && chown -R cves:cves /app
USER 1001

EXPOSE 8005

CMD ["python", "-m", "uvicorn", "js_intelligence.main:app", \
     "--host", "0.0.0.0", "--port", "8005", "--workers", "1"]
