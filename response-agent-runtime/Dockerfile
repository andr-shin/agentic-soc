FROM public.ecr.aws/docker/library/python:3.11-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
COPY tools/ tools/
EXPOSE 8080
CMD ["opentelemetry-instrument", "python", "server.py"]
