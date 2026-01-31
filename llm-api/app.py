import os
import time
import logging
import jwt
import requests
import json
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# CORS
CORS(app, resources={r"/api/*": {"origins": os.environ.get("CORS_ORIGINS", "*").split(",")}})

# Database Configuration
POSTGRES_USER = os.environ.get("POSTGRES_USER", "postgres")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "postgres")
POSTGRES_DB = os.environ.get("POSTGRES_DB", "chatdb")
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "postgres")
app.config['SQLALCHEMY_DATABASE_URI'] = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}/{POSTGRES_DB}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Models
class ChatSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_email = db.Column(db.String(255), nullable=False)
    title = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    messages = db.relationship('ChatMessage', backref='session', lazy=True, cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "title": self.title,
            "created_at": self.created_at.isoformat()
        }

class ChatMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.Integer, db.ForeignKey('chat_session.id'), nullable=False)
    role = db.Column(db.String(50), nullable=False) # 'user' or 'assistant'
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "role": self.role,
            "content": self.content,
            "created_at": self.created_at.isoformat()
        }

# Rate limiting
REDIS_URL = os.environ.get("REDIS_URL")
if REDIS_URL:
    logger.info(f"Using Redis for rate limiting: {REDIS_URL}")
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per hour"],
        storage_uri=REDIS_URL
    )
else:
    logger.warning("Using in-memory storage for rate limiting (not recommended for production).")
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per hour"]
    )

# Configuration
PUBLIC_KEY_PATH = "/app/keys/public_key.pem"
OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://ollama:11434")
DEFAULT_MODEL = os.environ.get("DEFAULT_MODEL", "llama3")
ALLOWED_USERS = os.environ.get("ALLOWED_USERS", "").split(",")
ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "gapps.fi").split(",")

public_key = None

def load_public_key():
    """Loads the public key from the shared volume. Retries if not found."""
    global public_key
    retries = 30
    while retries > 0:
        if os.path.exists(PUBLIC_KEY_PATH):
            try:
                with open(PUBLIC_KEY_PATH, "rb") as f:
                    public_key = serialization.load_pem_public_key(f.read())
                print("Public key loaded successfully.")
                return
            except Exception as e:
                print(f"Error reading public key: {e}")
        else:
            print(f"Public key not found at {PUBLIC_KEY_PATH}. Waiting...")
        
        time.sleep(2)
        retries -= 1
    
    print("Failed to load public key after multiple retries.")

# Initialize database and load key with retry
with app.app_context():
    db_retries = 5
    while db_retries > 0:
        try:
            db.create_all()
            logger.info("Database initialized successfully.")
            break
        except Exception as e:
            logger.warning(f"Database initialization failed, retrying in 5s... ({e})")
            time.sleep(5)
            db_retries -= 1
    if db_retries == 0:
        logger.error("Failed to initialize database after multiple retries.")
    
    load_public_key()

@app.after_request
def add_security_headers(response):
    """Add security headers to all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Cache-Control'] = 'no-store'
    response.headers['Content-Security-Policy'] = "default-src 'none'; frame-ancestors 'none'"
    return response

def verify_token(token):
    """Verifies the JWT token using the loaded public key."""
    global public_key
    if not public_key:
        load_public_key()
        if not public_key:
            return {"error": "Public key not available to verify token"}, 503

    try:
        # First attempt with current public key
        decoded = jwt.decode(
            token,
            public_key,
            algorithms=["RS256"],
            audience="llm-api",
            issuer="auth-service"
        )
    except Exception as e:
        # If it fails, maybe the key was rotated? Retry reloading once.
        logger.info("Token verification failed. Attempting to reload public key...")
        load_public_key()
        try:
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience="llm-api",
                issuer="auth-service"
            )
            logger.info("Token verified successfully after key reload.")
        except Exception as retry_err:
            logger.error(f"Verification failed after reload: {retry_err}")
            return {"error": f"Invalid token: {str(e)}"}, 401
    
    # Authorization logic
    user_email = decoded.get("sub")
    user_role = decoded.get("role", "user")
    
    # Admins are always allowed
    if user_role == "admin":
        return decoded, 200

    # Domain/User whitelist check for non-admins
    is_user_allowed = user_email in ALLOWED_USERS
    is_domain_allowed = any(user_email.endswith(f"@{domain}") for domain in ALLOWED_DOMAINS if domain)
    
    if not (is_user_allowed or is_domain_allowed):
        logger.warning(f"Unauthorized access attempt by {user_email} (domain: {user_email.split('@')[-1] if '@' in user_email else 'unknown'})")
        return {"error": f"User {user_email} is not authorized for this domain. Please contact your administrator."}, 403

    return decoded, 200

@app.before_request
def authenticate():
    if request.method == "OPTIONS" or request.path == "/health":
        return

    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "Missing or invalid Authorization header"}), 401

    token = auth_header.split(" ")[1]
    response, status_code = verify_token(token)
    
    if status_code != 200:
        return jsonify(response), status_code
    
    request.user = response

def proxy_to_ollama(path, user_email, session_id=None):
    """Proxies the request to the Ollama service and saves to DB."""
    target_url = f"{OLLAMA_HOST}{path}"
    
    headers = {key: value for (key, value) in request.headers if key.lower() not in ['host', 'authorization', 'content-length']}
    
    if not request.is_json:
        return jsonify({"error": "JSON body required"}), 400

    data = request.get_json()
    if not data.get("model"):
        data["model"] = DEFAULT_MODEL
    
    # Explicitly disable streaming to avoid ndjson parsing issues
    data["stream"] = False

    user_message_content = data.get("message") or data.get("prompt")
    if not user_message_content and "messages" in data:
        user_message_content = data["messages"][-1]["content"]

    # Session handling
    if not session_id:
        # Create new session
        title = user_message_content[:50] + "..." if user_message_content else "New Chat"
        new_session = ChatSession(user_email=user_email, title=title)
        db.session.add(new_session)
        db.session.commit()
        session_id = new_session.id
    else:
        # Verify session belongs to user
        session = ChatSession.query.get(session_id)
        if not session or session.user_email != user_email:
            return jsonify({"error": "Session not found or access denied"}), 404

    # Save user message
    user_msg = ChatMessage(session_id=session_id, role='user', content=user_message_content)
    db.session.add(user_msg)
    db.session.commit()

    # Prep Ollama request (Ollama /api/chat expects list of messages)
    if path == '/api/chat':
        # Load history for Ollama context
        history = ChatMessage.query.filter_by(session_id=session_id).order_by(ChatMessage.created_at.asc()).all()
        data["messages"] = [{"role": m.role, "content": m.content} for m in history]
    
    try:
        # We don't stream to simplify DB persistence for now. 
        # For actual streaming, we would need to accumulate the response.
        logger.info(f"Proxying request to Ollama: {target_url} with model {data.get('model')}")
        resp = requests.post(
            url=target_url,
            headers=headers,
            json=data,
            stream=False, # Using non-streaming for easier DB integration
            timeout=120 # Add a generous timeout
        )
        
        logger.info(f"Ollama response status: {resp.status_code}")
        
        if resp.status_code == 200:
            resp_data = resp.json()
            assistant_content = ""
            if 'message' in resp_data:
                assistant_content = resp_data['message']['content']
            elif 'response' in resp_data:
                assistant_content = resp_data['response']
            
            # Save assistant response
            assistant_msg = ChatMessage(session_id=session_id, role='assistant', content=assistant_content)
            db.session.add(assistant_msg)
            db.session.commit()

            # Return full state for UI convenience
            all_messages = ChatMessage.query.filter_by(session_id=session_id).order_by(ChatMessage.created_at.asc()).all()
            return jsonify({
                "session_id": session_id,
                "messages": [m.to_dict() for m in all_messages]
            })
        
        return Response(resp.content, status=resp.status_code, headers=dict(resp.headers))

    except Exception as e:
        logger.error(f"Error proxying to Ollama: {e}")
        return jsonify({"error": str(e)}), 502

@app.route('/api/chat', methods=['POST'])
@limiter.limit("60 per minute")
def chat():
    user_email = request.user.get('sub')
    data = request.json
    session_id = data.get('session_id')
    logger.info(f"Chat request from {user_email} (session: {session_id})")
    
    try:
        return proxy_to_ollama('/api/chat', user_email, session_id)
    except Exception as e:
        logger.error(f"Chat execution failed: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/sessions', methods=['GET'])
@limiter.limit("60 per minute")
def list_sessions():
    user_email = request.user.get('sub')
    sessions = ChatSession.query.filter_by(user_email=user_email).order_by(ChatSession.created_at.desc()).all()
    return jsonify([s.to_dict() for s in sessions])

@app.route('/api/sessions/<int:session_id>', methods=['GET'])
@limiter.limit("60 per minute")
def get_session(session_id):
    user_email = request.user.get('sub')
    session = ChatSession.query.get(session_id)
    if not session or session.user_email != user_email:
        return jsonify({"error": "Session not found"}), 404
    
    messages = ChatMessage.query.filter_by(session_id=session_id).order_by(ChatMessage.created_at.asc()).all()
    return jsonify({
        "session": session.to_dict(),
        "messages": [m.to_dict() for m in messages]
    })

@app.route('/api/sessions/<int:session_id>', methods=['DELETE'])
@limiter.limit("60 per minute")
def delete_session(session_id):
    user_email = request.user.get('sub')
    session = ChatSession.query.get(session_id)
    if not session or session.user_email != user_email:
        return jsonify({"error": "Session not found"}), 404
    
    db.session.delete(session)
    db.session.commit()
    return jsonify({"message": "Session deleted"})

@app.route('/health', methods=['GET'])
@limiter.exempt
def health():
    try:
        ollama_resp = requests.get(f"{OLLAMA_HOST}/api/tags", timeout=2)
        ollama_ok = ollama_resp.status_code == 200
        # Test DB connection
        db.session.execute(db.text('SELECT 1'))
        db_ok = True
    except Exception:
        ollama_ok = False
        db_ok = False
    return jsonify({"status": "ok", "ollama_connected": ollama_ok, "db_connected": db_ok})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
