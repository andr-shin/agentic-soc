FROM public.ecr.aws/docker/library/python:3.11-slim-bookworm

# Install minimal dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY server.py .
COPY tools/ tools/

# Expose AgentCore Runtime required port
EXPOSE 8080

CMD ["opentelemetry-instrument", "python", "server.py"]
