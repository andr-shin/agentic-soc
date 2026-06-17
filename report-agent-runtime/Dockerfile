FROM public.ecr.aws/docker/library/python:3.12-slim-bookworm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY server.py .
EXPOSE 8080
CMD ["opentelemetry-instrument", "python", "server.py"]
