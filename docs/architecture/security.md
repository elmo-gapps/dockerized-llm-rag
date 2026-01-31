# Security Posture: Defense-in-Depth

The Enterprise LLM Hosting solution is built on a "Privacy First, Zero Trust" architecture. This document outlines the security controls implemented to protect sensitive data and model integrity.

## 1. Network Security

### 1.1 Micro-Perimeter Isolation
All backend services (`Ollama`, `Postgres`, `Redis`) are deployed on a private internal bridge network (`llm-net`).
- **Control**: These services do not expose ports to the host machine.
- **Access**: Only the `LLM API Gateway` and `Auth Service` can reach the internal components.

### 1.2 Ingress Control
Entrance to the stack is restricted to the two public-facing containers:
- **Chat UI**: Port 8080 (Public/Host).
- **LLM API**: Port 5002 (Host).
- **Auth Service**: Port 5001 (Host - limited to 127.0.0.1 by default in production recommendation).

## 2. Identity & Access Management (IAM)

### 2.1 Asymmetric JWT Authentication
We utilize **RS256** (RSA with SHA-256) for session tokens.
- **Advantage**: The private key never leaves the `Auth Service`. The `LLM API` only requires the public key for validation, minimizing the impact of a potential container breach.
- **TTL**: Tokens have a default 1-hour expiration, minimizing the window for token theft exploitation.

### 2.2 Domain-Level Authorization
The system supports whitelist-based authorization:
- `ALLOWED_DOMAINS`: Automatically authorizes any user from specific organizational domains.
- `ALLOWED_USERS`: Granular control for specific external collaborators.

## 3. Data Protection

### 3.1 Data Sovereignty (Local Execution)
Contrary to SaaS LLM providers, user prompts and model responses never transit the public internet. 
- **Inference**: Occurs entirely on-premises/in-container.
- **Learning**: The models used (Ollama-based) are not updated with user data during inference, preventing "data leakage" into the model weights.

### 3.2 Encryption at Rest
While the solution relies on standard Docker volume mounts, it is recommended that the underlying host uses:
- LUKS/Filevault encryption for volume storage.
- Encrypted S3 buckets if backing up database dumps.

## 4. Operational Security

### 4.1 Rate Limiting
To prevent Denial of Service (DoS) and resource exhaustion (GPU/VRAM pinning), rate limiting is enforced at two levels:
- **Auth Level**: Prevents brute-force attacks on user credentials.
- **API Level**: Prevents excessive inference requests that could starve other users of GPU resources.

### 4.2 Security Headers
All Flask-based services inject hardened security headers:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy`: Restricts where data can be sent or loaded from.
