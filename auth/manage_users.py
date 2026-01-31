#!/usr/bin/env python3
"""User management CLI for the auth service.

Usage:
    python manage_users.py add <email> <password> [role]
    python manage_users.py remove <email>
    python manage_users.py list
    python manage_users.py hash <password>

    Roles: admin, user (default)
"""

import sys
import json
import bcrypt
import os

USERS_FILE = os.environ.get("USERS_FILE", "/app/data/users.json")


def load_users():
    """Load users from JSON file."""
    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}


def save_users(users):
    """Save users to JSON file."""
    # Ensure directory exists
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=2)
    
    try:
        os.chmod(USERS_FILE, 0o600)  # Restrict permissions
    except OSError:
        pass  # Might fail on some filesystems or if not owner


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def add_user(email: str, password: str, role: str = "user"):
    """Add a new user with hashed password and role."""
    users = load_users()
    if email in users:
        print(f"User {email} already exists. Updating password/role.")
    
    users[email] = {
        "password": hash_password(password),
        "role": role
    }
    save_users(users)
    print(f"User {email} added/updated successfully with role '{role}'.")


def remove_user(email: str):
    """Remove a user."""
    users = load_users()
    if email in users:
        del users[email]
        save_users(users)
        print(f"User {email} removed.")
    else:
        print(f"User {email} not found.")


def list_users():
    """List all users."""
    users = load_users()
    if users:
        print("Registered users:")
        for email, data in users.items():
            role = data.get("role", "user") if isinstance(data, dict) else "legacy"
            print(f"  - {email} [{role}]")
    else:
        print("No users registered.")


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    
    command = sys.argv[1]
    
    if command == "add" and len(sys.argv) >= 4:
        email = sys.argv[2]
        password = sys.argv[3]
        role = sys.argv[4] if len(sys.argv) > 4 else "user"
        add_user(email, password, role)
    elif command == "remove" and len(sys.argv) == 3:
        remove_user(sys.argv[2])
    elif command == "list":
        list_users()
    elif command == "hash" and len(sys.argv) == 3:
        print(hash_password(sys.argv[2]))
    else:
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
