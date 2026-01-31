# Auth Service

The **Auth Service** is a Flask-based identity provider responsible for authenticating users and issuing RSA-signed JSON Web Tokens (JWTs).

## 🔑 Key Features
- **RS256 Signing**: Uses asymmetric RSA keys (2048-bit) to sign tokens, allowing for secure verification without sharing secrets.
- **Dynamic Key Generation**: Automatically generates a new RSA key pair on startup if none are found in `/app/keys/`.
- **Stateless Authentication**: Issues JWTs with a 1-hour expiration time.

## 🛠️ Configuration
The service is configured via environment variables:
| Variable | Default | Description |
| :--- | :--- | :--- |
| `ADMIN_USER` | `elmo.visuri@gmail.com` | Primary administrator email. |
| `ADMIN_PASSWORD` | `changeme` | Password for the administrator. |
| `ALLOWED_DOMAINS` | `gapps.fi` | Domains authorized for shared login. |
| `TOKEN_EXPIRATION_HOURS` | `1` | TTL for issued JWTs (e.g., 1, 24). |
| `REDIS_URL` | (None) | If set, uses Redis for rate limiting (recommended for prod). |

## 📡 API Endpoints

### `POST /login`
Authenticates a user and returns a signed JWT.
- **Payload**:
  ```json
  { "email": "admin@example.com", "password": "password" }
  ```
- **Response**:
  ```json
  { "token": "..." }
  ```

### `GET /health`
Returns the operational status of the service.

### User Management API (Admin Only)

The following endpoints allow managing users programmatically. They require a valid Bearer Token with the `admin` role.

#### `GET /users`
List all registered users.
- **Response**: `[{"email": "...", "role": "..."}, ...]`

#### `POST /users`
Create or update a user.
- **Payload**:
  ```json
  { "email": "user@example.com", "password": "securePass", "role": "user" }
  ```
- **Response**: `{"message": "User saved", ...}`

#### `DELETE /users/<email>`
Remove a user by email.
- **Response**: `{"message": "User removed"}`

## 🛡️ Security Details
- **Token Claims**:
  - `iss`: `auth-service`
  - `aud`: `llm-api`
  - `sub`: User email
  - `exp`: 1 hour from issuance
- **Key Storage**: Keys are stored in the `/app/keys` directory, which is shared with the LLM API via a Docker volume.
