# AI Correlation Layer — Dockerfile
FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir uv==0.5.14

# Copy workspace libs first for layer caching
COPY libs/db-base ./libs/db-base
COPY libs/event-schemas ./libs/event-schemas
COPY libs/kafka-client ./libs/kafka-client
COPY libs/observability ./libs/observability
COPY libs/security ./libs/security

# Copy service
COPY services/ai-correlation-layer ./services/ai-correlation-layer

# Install all dependencies (including scikit-learn, numpy, openai, redis)
RUN uv pip install --system --no-cache \
    -e ./libs/db-base \
    -e ./libs/event-schemas \
    -e ./libs/kafka-client \
    -e ./libs/observability \
    -e ./libs/security \
    -e ./services/ai-correlation-layer

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8008

EXPOSE 8008

CMD ["python", "-m", "uvicorn", "ai_correlation.main:app", \
     "--host", "0.0.0.0", "--port", "8008", "--workers", "1"]
