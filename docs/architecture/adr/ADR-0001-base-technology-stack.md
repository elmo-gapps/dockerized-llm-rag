# ADR-0001: Foundational Technology Stack Selection

## Status
Accepted

## Context
We need to build a containerized environment for hosting LLMs that is secure, scalable, and easy to maintain for enterprise users. The primary constraints are data sovereignty, local-first execution, and ease of deployment.

## Decision
The foundational stack will consist of:
1.  **Inference Engine**: Ollama (for its ease of model management and performance).
2.  **API Layer**: Python/Flask (for its flexibility and strong integration with AI/ML libraries).
3.  **Persistence**: PostgreSQL 18 (for enterprise-grade relational storage of chat history).
4.  **Auth Protocol**: RS256 JWTs (for decoupled, stateless authentication).
5.  **State/Cache**: Redis (optional, for scalable rate limiting).

## Rationale

### Ollama vs. vLLM/LocalAI
- **Ollama** provides a single-binary solution for model management and inference with excellent support for MacOS (local dev) and Linux (production).
- It simplifies the "pull model" workflow compared to vLLM, which is more focused on high-throughput server environments but has a much larger image footprint.

### PostgreSQL vs. SQLite/MongoDB
- **PostgreSQL 18** offers mature ACID compliance, JSONB support for message storage, and robust backup/restore tooling essential for enterprise environments.
- SQLite was rejected due to concurrency limitations with multiple containers writing to a shared volume.

### RS256 JWTs vs. Shared Secret (HS256)
- **RS256** allows the `LLM API` to verify tokens without knowing the private key used by the `Auth Service`. This follows the principle of least privilege and enhances security in microservices.

## Consequences
- **Positive**: Clear separation of concerns; high security for token validation; robust data persistence.
- **Negative**: Increased complexity compared to a monolithic architecture; requires managing more containers and networked services.
