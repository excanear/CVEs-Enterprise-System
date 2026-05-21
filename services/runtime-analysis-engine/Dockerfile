# Runtime Analysis Engine — Dockerfile
# Base: official Playwright Python image (includes Chromium + all OS deps)
FROM mcr.microsoft.com/playwright/python:v1.60.0-jammy

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
COPY services/runtime-analysis-engine ./services/runtime-analysis-engine

# Install all dependencies in a venv
RUN uv pip install --system --no-cache \
    -e ./libs/db-base \
    -e ./libs/event-schemas \
    -e ./libs/kafka-client \
    -e ./libs/observability \
    -e ./libs/security \
    -e ./services/runtime-analysis-engine

# Playwright browsers are pre-installed in the base image
# No extra playwright install step needed

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8004

# Non-root user — required so Chromium kernel sandbox works (no --no-sandbox)
RUN groupadd -r cves --gid 1001 \
    && useradd -r -u 1001 -g cves --no-create-home cves \
    && chown -R cves:cves /app
USER 1001

EXPOSE 8004

CMD ["python", "-m", "uvicorn", "runtime_analysis.main:app", \
     "--host", "0.0.0.0", "--port", "8004", "--workers", "1"]
