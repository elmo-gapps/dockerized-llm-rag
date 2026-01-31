#!/bin/bash
# Wrapper script to manage users in the running auth-service container

if [ -z "$(docker ps -q -f name=auth-service)" ]; then
    echo "Error: auth-service container is not running."
    echo "Please start the stack with 'docker-compose up -d'"
    exit 1
fi

docker exec -it auth-service python manage_users.py "$@"
