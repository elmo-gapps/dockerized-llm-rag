FROM python:3.13-slim

WORKDIR /app

# Create a non-root user
RUN useradd -m -u 1000 appuser

# Install curl and postgres build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gcc \
    libc-dev \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py app.py

# Create directory for keys and set permissions (read-only for appuser effectively via mount, 
# but directory needs to exist)
RUN mkdir -p /app/keys && chown -R appuser:appuser /app/keys

USER appuser

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/health || exit 1

CMD ["gunicorn", "--timeout", "300", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
