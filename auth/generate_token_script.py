import sys
import os
import datetime
import jwt
from cryptography.hazmat.primitives import serialization

# Configuration
PRIVATE_KEY_PATH = "/app/keys/private_key.pem"
TOKEN_EXPIRATION_HOURS = int(os.environ.get("TOKEN_EXPIRATION_HOURS", "1"))

def generate_token(email):
    if not os.path.exists(PRIVATE_KEY_PATH):
        print(f"Error: Private key not found at {PRIVATE_KEY_PATH}")
        sys.exit(1)

    with open(PRIVATE_KEY_PATH, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        "iss": "auth-service",
        "sub": email,
        "aud": "llm-api",
        "exp": now + datetime.timedelta(hours=TOKEN_EXPIRATION_HOURS),
        "iat": now
    }
    
    token = jwt.encode(payload, private_key, algorithm="RS256")
    print(f"Token for {email}:")
    print(token)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python generate_token_script.py <email>")
        sys.exit(1)
    
    email = sys.argv[1]
    generate_token(email)
