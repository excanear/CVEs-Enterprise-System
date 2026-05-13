# Exposure Validation Engine — Dockerfile
# Playwright base includes Chromium for on-demand SPA probing
FROM mcr.microsoft.com/playwright/python:v1.49.0-jammy

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
COPY services/exposure-validation-engine ./services/exposure-validation-engine

# Install all dependencies
RUN uv pip install --system --no-cache \
    -e ./libs/db-base \
    -e ./libs/event-schemas \
    -e ./libs/kafka-client \
    -e ./libs/observability \
    -e ./libs/security \
    -e ./services/exposure-validation-engine

# Playwright browsers are pre-installed in the base image
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8006

EXPOSE 8006

CMD ["python", "-m", "uvicorn", "exposure_validation.main:app", \
     "--host", "0.0.0.0", "--port", "8006", "--workers", "1"]
