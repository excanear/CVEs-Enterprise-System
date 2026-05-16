# Scan Orchestrator — Dockerfile
FROM python:3.14-slim AS base

WORKDIR /app

RUN pip install --no-cache-dir uv==0.5.14

# Copy workspace libs first for layer caching
COPY libs/db-base ./libs/db-base
COPY libs/event-schemas ./libs/event-schemas
COPY libs/kafka-client ./libs/kafka-client
COPY libs/observability ./libs/observability
COPY libs/security ./libs/security

# Copy service
COPY services/scan-orchestrator ./services/scan-orchestrator

# Install all dependencies
RUN uv pip install --system --no-cache \
    -e ./libs/db-base \
    -e ./libs/event-schemas \
    -e ./libs/kafka-client \
    -e ./libs/observability \
    -e ./libs/security \
    -e ./services/scan-orchestrator

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8000

RUN addgroup --system --gid 1001 cves \
    && adduser --system --uid 1001 --gid 1001 --no-create-home cves \
    && chown -R cves:cves /app
USER 1001

EXPOSE 8000

CMD ["python", "-m", "uvicorn", "scan_orchestrator.main:app", \
     "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
