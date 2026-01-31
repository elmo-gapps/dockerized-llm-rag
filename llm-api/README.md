# LLM API Gateway

The **LLM API Gateway** is a secure proxy that bridges user requests to the **Ollama** inference engine. It enforces authentication, authorization, and ensures that only valid requests from authorized domains reach the backend LLM.

## 🛡️ Key Features
- **JWT Authentication**: Validates RSA-signed tokens issued by the `auth-service`.
- **Domain-Based Authorization**: Automatically grants access to users from verified organization domains (e.g., `@gapps.fi`).
- **Identity Enforcement**: Restricts access to a curated list of authorized emails (`ALLOWED_USERS`).
- **Self-Healing Key Sync**: Automatically reloads the verification key if signature failure is detected (handles key rotation).
- **Ollama Proxying**: Transparently forwards requests to Ollama's native API.

## 🛠️ Configuration
| Variable | Default | Description |
| :--- | :--- | :--- |
| `OLLAMA_HOST` | `http://ollama:11434` | URL of the Ollama backend. |
| `DEFAULT_MODEL` | `gemma3` | Model to use if not specified in the request. |
| `ALLOWED_DOMAINS` | `gapps.fi` | Authorized email domains. |
| `ALLOWED_USERS` | (None) | Authorized specific email addresses. |
| `CORS_ORIGINS` | `*` | Comma-separated list of allowed origins. |
| `REDIS_URL` | (None) | If set, uses Redis for rate limiting (recommended for prod). |

## 🛡️ Security Controls for Production

The project is built on the principle of **Data Sovereignty**:

1.  **Local Inference**: No user prompt data or model weights are ever transmitted to external AI providers.
2.  **Network Perimeter**: The `ollama` and `auth-service` reside on a private internal network. Only the gateway is exposed.
3.  **Zero-Trust Identity**: Even internal service-to-service communication requires token-based identification.

## 📡 API Endpoints

### `POST /api/generate`
Proxies text completion requests to Ollama.
- **Authentication**: Required (Bearer Token).

### `POST /api/chat`
Proxies chat completion requests to Ollama.
- **Authentication**: Required (Bearer Token).

### `GET /health`
Validates connectivity with the Ollama backend and overall service health.
