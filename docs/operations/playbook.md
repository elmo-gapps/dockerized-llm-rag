# Operations Playbook: Manage & Scale

This document provides operational procedures for maintaining and scaling the Enterprise LLM platform.

## 1. Backup and Recovery

### 1.1 Chat History (PostgreSQL)
The chat history is the most critical data.
- **Backup**:
  ```bash
  docker exec postgres pg_dump -U postgres chatdb > backup_$(date +%Y%m%d).sql
  ```
- **Restore**:
  ```bash
  cat backup.sql | docker exec -i postgres psql -U postgres chatdb
  ```

### 1.2 User Accounts & Keys
The `auth-service` stores user hashes and RSA keys in volumes.
- **Users**: Copy `auth_data/users.json` to secure storage.
- **Keys**: Copy `jwks_data/*.pem` to secure storage. **CAUTION**: Losing the private key will invalidate all existing JWTs.

## 2. Resource Management

### 2.1 GPU Allocation
To enable GPU support for the inference engine, Ensure the `nvidia-container-toolkit` is installed on the host.
Update `docker-compose.yml`:
```yaml
deploy:
  resources:
    reservations:
      devices:
        - driver: nvidia
          count: 1
          capabilities: [gpu]
```

### 2.2 Memory Constraints
LLMs are memory-intensive. It is recommended to set memory limits on the `ollama` container to prevent host system crashes:
```yaml
mem_limit: 8G
mem_reservation: 4G
```

## 3. Scaling Strategies

### 3.1 Horizontal Scaling
- **API/UI**: Can be scaled to multiple replicas using a load balancer (Nginx/Traefik).
- **Auth**: Can be scaled if using a shared persistence layer (e.g., migrating from `users.json` to a Shared Database).

### 3.2 Ollama Pooling
For high-demand environments, consider front-ending multiple Ollama instances with **LiteLLM** or a similar round-robin proxy. This allows distributing inference load across multiple GPUs/Hosts.

## 4. Monitoring & Health

All services expose a `/health` endpoint:
- `http://localhost:5001/health` (Auth Service)
- `http://localhost:5002/health` (LLM API - Includes DB and Ollama connectivity check)

### Log Aggregation
For production, it is recommended to redirect Docker logs to a centralized collector (e.g., ELK Stack or Datadog):
```bash
docker-compose logs -f --tail=100
```
