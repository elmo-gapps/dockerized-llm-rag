import os
import json
import datetime
import logging
import bcrypt
import jwt
import functools
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
CORS(app) # Enable CORS for all routes

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Rate limiting
# Rate limiting
REDIS_URL = os.environ.get("REDIS_URL")
if REDIS_URL:
    logger.info(f"Using Redis for rate limiting: {REDIS_URL}")
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["100 per hour"],
        storage_uri=REDIS_URL
    )
else:
    logger.warning("Using in-memory storage for rate limiting (not recommended for production).")
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["100 per hour"]
    )

# Configuration
PRIVATE_KEY_PATH = "/app/keys/private_key.pem"
PUBLIC_KEY_PATH = "/app/keys/public_key.pem"
USERS_FILE = os.environ.get("USERS_FILE", "/app/data/users.json")
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "").split(",")
TOKEN_EXPIRATION_HOURS = int(os.environ.get("TOKEN_EXPIRATION_HOURS", "1"))

# Legacy fallback (will be removed once users are migrated)
ADMIN_USER = os.environ.get("ADMIN_USER", "")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")

private_key = None


def load_users():
    """Load users from JSON file."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading users file: {e}")
    return {}


def save_users(users):
    """Save users to JSON file."""
    try:
        os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
        with open(USERS_FILE, "w") as f:
            json.dump(users, f, indent=2)
        try:
            os.chmod(USERS_FILE, 0o600)
        except OSError:
            pass
    except Exception as e:
        logger.error(f"Error saving users file: {e}")


def verify_password(password: str, hashed: str) -> bool:
    """Verify a password against its bcrypt hash."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))
    except Exception:
        return False


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def generate_keys():
    """Generates RSA key pair if not exists."""
    global private_key
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        logger.info("Keys already exist. Loading...")
        with open(PRIVATE_KEY_PATH, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        return

    logger.info("Generating new RSA keys...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
    )
    
    # Save private key
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save public key
    public_key = private_key.public_key()
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    logger.info("Keys generated and saved.")


# Load keys on startup if they exist
# Generation is now handled by start.sh to avoid worker race conditions
with app.app_context():
    if os.path.exists(PRIVATE_KEY_PATH):
        try:
            with open(PRIVATE_KEY_PATH, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            logger.info("RSA Private key loaded.")
        except Exception as e:
            logger.error(f"Error loading private key: {e}")
    else:
        logger.warning(f"Private key not found at {PRIVATE_KEY_PATH}. It must be generated before the service can issue tokens.")

def ensure_key_loaded():
    """Ensure private key is loaded, trying to load it if it's currently None."""
    global private_key
    if private_key is None:
        if os.path.exists(PRIVATE_KEY_PATH):
            with open(PRIVATE_KEY_PATH, "rb") as f:
                private_key = serialization.load_pem_private_key(f.read(), password=None)
            logger.info("RSA Private key loaded on-demand.")
    return private_key is not None


@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
    return response


def is_user_authorized(email: str) -> bool:
    """Check if user's email domain is in the allowed list."""
    return any(email.endswith(f"@{domain}") for domain in ALLOWED_DOMAINS if domain)


def authenticate_user(email: str, password: str) -> tuple[bool, str]:
    """Authenticate user and return (success, role)."""
    users = load_users()
    
    # Check user file first
    if email in users:
        user_data = users[email]
        # Handle legacy string format or new dict format
        if isinstance(user_data, str):
            if verify_password(password, user_data):
                return True, "user"
        elif isinstance(user_data, dict):
            if verify_password(password, user_data.get("password", "")):
                return True, user_data.get("role", "user")
    
    # Legacy fallback: env-based admin
    if ADMIN_USER and ADMIN_PASSWORD:
        if email == ADMIN_USER and password == ADMIN_PASSWORD:
            logger.warning(f"User {email} authenticated via legacy env credentials.")
            return True, "admin"
    
    return False, ""


def require_admin(f):
    """Decorator to require admin role."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "Missing authorization"}), 401
        
        token = auth_header.split(" ")[1]
        try:
            # We verify signature using our own public key (loaded from private key)
            if not ensure_key_loaded():
                 return jsonify({"error": "Encryption keys not initialized"}), 503
                 
            public_key = private_key.public_key()
            decoded = jwt.decode(token, public_key, algorithms=["RS256"], audience="llm-api", options={"verify_aud": False})
            
            # Verify admin role
            if decoded.get("role") != "admin":
                 return jsonify({"error": "Admin privileges required"}), 403
                 
        except Exception as e:
            return jsonify({"error": f"Invalid token: {str(e)}"}), 401
            
        return f(*args, **kwargs)
    return decorated_function


@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON body"}), 400

    email = data.get("email")
    password = data.get("password")

    logger.info(f"Login attempt for email: {email}")

    if not email or not password:
        logger.warning("Email or password missing in request")
        return jsonify({"error": "Email and password required"}), 400

    # Check domain authorization
    authorized_domain = is_user_authorized(email)
    logger.info(f"Domain authorized for {email}: {authorized_domain}")

    success, role = authenticate_user(email, password)
    logger.info(f"Authentication success for {email}: {success}, role: {role}")
    
    if success:
        if role != "admin" and not authorized_domain:
             logger.warning(f"Login REJECTED - unauthorized domain for {email}")
             return jsonify({"error": "Invalid credentials"}), 401

        if not ensure_key_loaded():
             logger.error("Login attempt failed: Private key not available for signing")
             return jsonify({"error": "Service temporarily unavailable (key error)"}), 503

        now = datetime.datetime.now(datetime.timezone.utc)
        payload = {
            "iss": "auth-service",
            "sub": email,
            "aud": "llm-api",
            "role": role,
            "exp": now + datetime.timedelta(hours=TOKEN_EXPIRATION_HOURS),
            "iat": now
        }
        
        token = jwt.encode(payload, private_key, algorithm="RS256")
        logger.info(f"Login SUCCESS for {email} (role={role})")
        return jsonify({"token": token})
    
    logger.warning(f"Login FAILED for {email}")
    return jsonify({"error": "Invalid credentials"}), 401


# --- User Management API ---

@app.route('/users', methods=['GET'])
@require_admin
def list_users_api():
    """List all users."""
    users = load_users()
    # Return list of {email, role}
    user_list = []
    for email, data in users.items():
        role = data.get("role", "user") if isinstance(data, dict) else "legacy"
        user_list.append({"email": email, "role": role})
    return jsonify(user_list)


@app.route('/users', methods=['POST'])
@require_admin
def create_user_api():
    """Create or update a user."""
    data = request.get_json()
    email = data.get("email")
    password = data.get("password")
    role = data.get("role", "user")
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
        
    users = load_users()
    users[email] = {
        "password": hash_password(password),
        "role": role
    }
    save_users(users)
    logger.info(f"User {email} created/updated by admin")
    return jsonify({"message": f"User {email} saved", "email": email, "role": role})


@app.route('/users/<email>', methods=['DELETE'])
@require_admin
def delete_user_api(email):
    """Delete a user."""
    users = load_users()
    if email in users:
        del users[email]
        save_users(users)
        logger.info(f"User {email} deleted by admin")
        return jsonify({"message": f"User {email} removed"})
    return jsonify({"error": "User not found"}), 404


@app.route('/health', methods=['GET'])
@limiter.exempt
def health():
    users = load_users()
    return jsonify({"status": "ok", "users_configured": len(users) > 0})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
