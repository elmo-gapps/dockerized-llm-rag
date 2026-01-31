FROM python:3.13-slim

WORKDIR /app

# Create a non-root user
RUN useradd -m -u 1000 appuser

# Install curl for healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py app.py
COPY manage_users.py manage_users.py
COPY start.sh start.sh
RUN chmod +x start.sh

# Create directory for keys and data, and set permissions
RUN mkdir -p /app/keys /app/data && chown -R appuser:appuser /app/keys /app/data

USER appuser

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5001/health || exit 1

ENTRYPOINT ["./start.sh"]
CMD ["gunicorn", "--timeout", "120", "-w", "4", "-b", "0.0.0.0:5001", "app:app"]
