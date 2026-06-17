FROM public.ecr.aws/docker/library/python:3.11-slim-bookworm

# Install dependencies for Steampipe
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Create steampipe user (Steampipe cannot run as root)
RUN useradd -m -s /bin/bash steampipe

# Install Steampipe (as root, then switch user)
ARG STEAMPIPE_VERSION=v1.1.1
RUN ARCH=$(dpkg --print-architecture) && \
    curl -sSL --retry 3 --retry-delay 5 \
    "https://github.com/turbot/steampipe/releases/download/${STEAMPIPE_VERSION}/steampipe_linux_${ARCH}.tar.gz" \
    -o /tmp/steampipe.tar.gz && \
    tar -xzf /tmp/steampipe.tar.gz -C /usr/local/bin && \
    rm /tmp/steampipe.tar.gz && \
    chmod +x /usr/local/bin/steampipe

USER steampipe
ENV HOME=/home/steampipe

# Install AWS plugin
RUN steampipe plugin install aws

# Switch back to root for app setup
USER root

# Set up application in steampipe user's home
WORKDIR /home/steampipe/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY tools/ tools/
RUN chown -R steampipe:steampipe /home/steampipe/app

# Environment variables for multi-account support (set via AgentCore Runtime config)
ENV TARGET_ACCOUNTS=""
ENV TARGET_REGIONS=""
ENV TARGET_ROLE_NAME="AgenticSOC-ReadOnly"

# Expose AgentCore Runtime required port
EXPOSE 8080

# Run as steampipe user for proper permissions
USER steampipe
WORKDIR /home/steampipe/app
CMD ["opentelemetry-instrument", "python", "server.py"]
