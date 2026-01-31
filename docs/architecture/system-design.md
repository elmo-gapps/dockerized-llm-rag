# System Design: Enterprise LLM Hosting

This document provides a technical deep-dive into the architecture, components, and data flow of the Enterprise LLM Hosting solution.

## 1. Architectural Overview

The solution follows a microservices architecture designed for local-first, secure inference. It leverages containerization to ensure consistency across environments while maintaining strict data sovereignty.

### C4 Context Diagram

```mermaid
C4Context
    title System Context Diagram for Enterprise LLM Hosting

    Person(user, "User/Stakeholder", "Consumes LLM services via the Chat UI.")
    System(llm_system, "LLM Hosting Platform", "Provides secure, authenticated access to Large Language Models.")
    
    Rel(user, llm_system, "Interacts with", "HTTPS/JSON")
```

### C4 Container Diagram

```mermaid
C4Container
    title Container Diagram for Enterprise LLM Hosting

    Person(user, "User", "Web Browser")
    
    System_Boundary(c1, "LLM Hosting Platform") {
        Container(ui, "Chat UI", "React, Vite, Tailwind v4", "Provides the user interface for chatting with LLMs.")
        Container(api, "LLM API Gateway", "Python, Flask, SQLAlchemy", "Enforces auth, manages chat sessions, and proxies to Ollama.")
        Container(auth, "Auth Service", "Python, Flask, cryptography", "Identity provider; issues and validates RS256 JWTs.")
        ContainerDb(db, "Chat Database", "PostgreSQL 18", "Stores chat sessions and message history.")
        Container(ollama, "Ollama Engine", "Go, C++", "Executes LLM inference (Gemma, Llama, etc.).")
        ContainerDb(redis, "Rate Limiter", "Redis", "Optional: Provides distributed rate limiting state.")
    }

    Rel(user, ui, "Uses", "Port 8080")
    Rel(ui, auth, "Authenticates", "JSON/POST")
    Rel(ui, api, "Sends Prompts", "JSON/POST (JWT)")
    Rel(api, db, "Persists History", "SQL")
    Rel(api, ollama, "Inference", "REST")
    Rel(api, auth, "Key Sync", "Shared Volume/JWKS")
    Rel(api, redis, "Checks Limits", "RESP")
```

## 2. Component Deep-Dive

### 2.1 Auth Service
- **Responsibility**: User lifecycle management and JWT issuance.
- **Security**: Uses **RS4096** (RSA-256) for signing. Keys are rotated on demand or generated on first boot.
- **Persistence**: User records are stored in `users.json` within a persistent Docker volume (`auth_data`).

### 2.2 LLM API Gateway
- **Responsibility**: Request orchestration, authorization, and persistence.
- **Verification**: Validates JWTs using the public key shared via `jwks_data`.
- **Session Management**: Automatically tracks chat history in Postgres 18.
- **Domain Enforcement**: Implements domain-based auto-authorization for enterprise emails.

### 2.3 Ollama Engine
- **Responsibility**: Inference execution.
- **Isolation**: Runs on an internal Docker network, inaccessible from the host except via the API Gateway.
- **Model Management**: Sidecar logic handles automatic model pulling during initialization.

## 3. Data Flow: Request Lifecycle

1.  **Authentication**:
    - User provides credentials to the `Chat UI`.
    - `Chat UI` calls `Auth Service` (`/login`).
    - `Auth Service` returns an RS256 JWT.
2.  **Inference**:
    - `Chat UI` sends a prompt + JWT to `LLM API Gateway` (`/api/chat`).
    - `LLM API Gateway` verifies the signature and checks `ALLOWED_DOMAINS`.
    - `LLM API Gateway` fetches/creates a Session in `Postgres`.
    - `LLM API Gateway` sends the prompt + history to `Ollama`.
    - `Ollama` returns the model response.
    - `LLM API Gateway` saves both user and assistant messages to `Postgres`.
    - `LLM API Gateway` returns the updated session state to the `Chat UI`.

## 4. Infrastructure & Scaling

- **Orchestration**: Docker Compose (Current), targetable for Kubernetes (K8s).
- **GPU Support**: Optional NVIDIA Container Toolkit integration via `docker-compose.yml`.
- **Scaling**: 
    - `LLM API Gateway` and `Chat UI` are stateless and can be scaled horizontally.
    - `Ollama` scaling requires GPU resource partitioning or a load balancer (e.g., LiteLLM).
