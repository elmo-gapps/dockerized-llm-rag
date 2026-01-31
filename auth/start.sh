#!/bin/bash
# start.sh

# Ensure keys are generated exactly once before starting gunicorn workers
echo "Starting Auth Service initialization..."

# We run the key generation logic from app.py using a one-off python command
# This avoids the race condition of multiple gunicorn workers trying to generate keys at once
python3 -c "from app import generate_keys; generate_keys()"

echo "Initialization complete. Starting Gunicorn..."
# Execute the CMD passed to the container
exec "$@"
