FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Install dependencies
COPY pyproject.toml .
COPY backend/ backend/
RUN uv pip install -e "." --system

# Generate self-signed certs if not mounted
COPY scripts/gen_certs.sh /gen_certs.sh
RUN chmod +x /gen_certs.sh

# Train ML model if not pre-trained
RUN mkdir -p backend/ml/data backend/ml

COPY . .

# Entrypoint
EXPOSE 8443 2525

CMD ["sh", "-c", "\
  if [ ! -f certs/server.crt ]; then bash /gen_certs.sh certs localhost; fi && \
  if [ ! -f backend/ml/pipeline.pkl ]; then \
    python -m backend.ml.download_data && python -m backend.ml.train; \
  fi && \
  python -m backend.app.main \
"]
