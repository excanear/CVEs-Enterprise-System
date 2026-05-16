# Asset Graph Engine — Dockerfile
# Lightweight: no browser (Playwright not needed for graph operations)
FROM python:3.14-slim

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
COPY services/asset-graph-engine ./services/asset-graph-engine

# Install all dependencies
RUN uv pip install --system --no-cache \
    -e ./libs/db-base \
    -e ./libs/event-schemas \
    -e ./libs/kafka-client \
    -e ./libs/observability \
    -e ./libs/security \
    -e ./services/asset-graph-engine

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8007

RUN addgroup --system --gid 1001 cves \
    && adduser --system --uid 1001 --gid 1001 --no-create-home cves \
    && chown -R cves:cves /app
USER 1001

EXPOSE 8007

CMD ["python", "-m", "uvicorn", "asset_graph.main:app", \
     "--host", "0.0.0.0", "--port", "8007", "--workers", "1"]
