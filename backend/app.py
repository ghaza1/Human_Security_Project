import os
from functools import wraps
from datetime import datetime
import requests
import jwt
from jwt import PyJWKClient

from sqlalchemy import create_engine, text
from sqlalchemy.exc import SQLAlchemyError

from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# CORS
CORS(app, resources={r"/*": {"origins": ["http://localhost:5500"]}})

#  Keycloak Config 
KEYCLOAK_BASE_URL = os.getenv("KEYCLOAK_BASE_URL", "http://localhost:8080")
REALM = os.getenv("KEYCLOAK_REALM", "secured-library")
AUDIENCE = os.getenv("KEYCLOAK_AUDIENCE", "backend-client")

OIDC_CONFIG_URL = f"{KEYCLOAK_BASE_URL}/realms/{REALM}/.well-known/openid-configuration"

_oidc = None
_jwks_client = None

# DB Config 
DATABASE_URL = os.getenv("DATABASE_URL")  # postgresql
engine = create_engine(DATABASE_URL, pool_pre_ping=True) if DATABASE_URL else None

#  Initialize Database 
def init_database():
    """Create tables if they don't exist"""
    if not engine:
        print("Database URL not set. Tables won't be created.")
        return
    
    try:
        with engine.begin() as conn:
            # Create books table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS books (
                    id SERIAL PRIMARY KEY,
                    title VARCHAR(255) NOT NULL,
                    author VARCHAR(255) NOT NULL,
                    available BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            
            # Create notes table
            conn.execute(text("""
                CREATE TABLE IF NOT EXISTS notes (
                    id SERIAL PRIMARY KEY,
                    user_id VARCHAR(255) NOT NULL,
                    username VARCHAR(255) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    content TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """))
            
            # Insert sample data if empty
            result = conn.execute(text("SELECT COUNT(*) FROM books"))
            if result.scalar() == 0:
                conn.execute(text("""
                    INSERT INTO books (title, author) VALUES
                    ('Human Security Principles', 'Dr. Alex Johnson'),
                    ('Zero Trust Architecture', 'Sarah Miller'),
                    ('Privacy Engineering', 'Michael Chen'),
                    ('Secure Software Development', 'Emily Davis')
                """))
        print("Database tables initialized successfully")
    except Exception as e:
        print(f"Database initialization failed: {e}")

# Call initialization
init_database()

# Keycloak Helpers 
def get_oidc():
    global _oidc, _jwks_client
    if _oidc is None:
        try:
            r = requests.get(OIDC_CONFIG_URL, timeout=10)
            r.raise_for_status()
            _oidc = r.json()
            _jwks_client = PyJWKClient(_oidc["jwks_uri"])
            print(f"Connected to Keycloak at {KEYCLOAK_BASE_URL}")
        except Exception as e:
            print(f"Failed to connect to Keycloak: {e}")
            raise
    return _oidc, _jwks_client


def extract_roles(payload: dict) -> set:
    roles = set(payload.get("realm_access", {}).get("roles", []))
    ra = payload.get("resource_access", {})
    for _, data in ra.items():
        roles.update(data.get("roles", []))
    return roles


def require_roles(required=None):
    required = set(required or [])

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer "):
                return jsonify(error="Missing bearer token"), 401

            token = auth.split(" ", 1)[1].strip()

            try:
                _, jwks_client = get_oidc()
                signing_key = jwks_client.get_signing_key_from_jwt(token).key

                payload = jwt.decode(
                    token,
                    signing_key,
                    algorithms=["RS256"],
                    audience=[AUDIENCE, "frontend-client", "backend-client", "account"],
                    options={"verify_exp": True},
                )

                user_roles = extract_roles(payload)

                if required and not (user_roles & required):
                    return jsonify(error="Forbidden (insufficient role)"), 403

                request.user = {
                    "username": payload.get("preferred_username", "unknown"),
                    "roles": sorted(list(user_roles)),
                    "user_id": payload.get("sub", ""),
                }

            except jwt.ExpiredSignatureError:
                return jsonify(error="Token expired"), 401
            except Exception as e:
                return jsonify(error="Invalid token", details=str(e)), 401

            return fn(*args, **kwargs)

        return wrapper

    return decorator


# Utils 
def _ensure_db():
    if engine is None:
        return False, (jsonify(error="DATABASE_URL is not set"), 500)
    return True, None


#  Public Endpoints 
@app.get("/public")
def public():
    return jsonify(message="Public endpoint - No authentication required"), 200


@app.get("/me")
@require_roles()
def me():
    return jsonify(user=request.user), 200


#  Health Check 
@app.get("/health")
def health_check():
    db_status = "connected" if engine else "disconnected"
    keycloak_status = "connected" if _oidc else "disconnected"
    
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "database": db_status,
        "keycloak": keycloak_status,
        "endpoints": {
            "public": "/public",
            "user_info": "/me",
            "health": "/health",
            "books": ["GET /books", "POST /books", "DELETE /books/:id"],
            "notes": ["GET /notes", "POST /notes", "DELETE /notes/:id"]
        }
    }), 200


# BOOKS Endpoints 
@app.get("/books")
@require_roles(["read_only", "crud_no_delete", "full_crud"])
def list_books():
    ok, resp = _ensure_db()
    if not ok:
        return resp

    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, title, author, available, created_at
                    FROM books
                    ORDER BY id
                """)
            )
            books = [dict(row) for row in result.mappings().all()]

        return jsonify(books=books), 200

    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


@app.post("/books")
@require_roles(["crud_no_delete", "full_crud"])
def create_book():
    ok, resp = _ensure_db()
    if not ok:
        return resp

    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    author = (data.get("author") or "").strip()

    if not title or not author:
        return jsonify(error="title and author are required"), 400

    try:
        with engine.begin() as conn:
            result = conn.execute(
                text("""
                    INSERT INTO books (title, author)
                    VALUES (:t, :a)
                    RETURNING id, title, author, available, created_at
                """),
                {"t": title, "a": author},
            )
            book = dict(result.mappings().first())

        return jsonify(book=book), 201

    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


@app.delete("/books/<int:book_id>")
@require_roles(["full_crud"])
def delete_book(book_id):
    ok, resp = _ensure_db()
    if not ok:
        return resp

    try:
        with engine.begin() as conn:
            res = conn.execute(
                text("DELETE FROM books WHERE id = :id"),
                {"id": book_id},
            )

        if res.rowcount == 0:
            return jsonify(error="Book not found"), 404

        return jsonify(message=f"Book {book_id} deleted successfully"), 200

    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


#  NOTES Endpoints
@app.get("/notes")
@require_roles(["read_only", "crud_no_delete", "full_crud"])
def list_notes():
    """Get all notes for the authenticated user"""
    ok, resp = _ensure_db()
    if not ok:
        return resp

    try:
        with engine.connect() as conn:
            result = conn.execute(
                text("""
                    SELECT id, title, content, created_at
                    FROM notes 
                    WHERE user_id = :user_id
                    ORDER BY created_at DESC
                """),
                {"user_id": request.user["user_id"]}
            )
            notes = [dict(row) for row in result.mappings().all()]

        return jsonify(notes=notes), 200

    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


@app.post("/notes")
@require_roles(["crud_no_delete", "full_crud"])
def create_note():
    """Create a new note for the authenticated user"""
    ok, resp = _ensure_db()
    if not ok:
        return resp

    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()
    content = (data.get("content") or "").strip()

    if not title:
        return jsonify(error="title is required"), 400

    try:
        with engine.begin() as conn:
            result = conn.execute(
                text("""
                    INSERT INTO notes (user_id, username, title, content)
                    VALUES (:user_id, :username, :title, :content)
                    RETURNING id, title, content, created_at
                """),
                {
                    "user_id": request.user["user_id"],
                    "username": request.user["username"],
                    "title": title,
                    "content": content
                }
            )
            note = dict(result.mappings().first())

        return jsonify(note=note), 201

    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


@app.delete("/notes/<int:note_id>")
@require_roles(["full_crud"])
def delete_note(note_id):
    """Delete a note (only if owned by the user)"""
    ok, resp = _ensure_db()
    if not ok:
        return resp

    try:
        with engine.begin() as conn:
            # Delete only if note belongs to the user
            res = conn.execute(
                text("""
                    DELETE FROM notes 
                    WHERE id = :id AND user_id = :user_id
                """),
                {
                    "id": note_id,
                    "user_id": request.user["user_id"]
                }
            )

        if res.rowcount == 0:
            return jsonify(error="Note not found or not authorized to delete"), 404

        return jsonify(message=f"Note {note_id} deleted successfully"), 200

    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


# Statistics Endpoint
@app.get("/stats")
@require_roles(["read_only", "crud_no_delete", "full_crud"])
def get_stats():
    """Get system statistics"""
    ok, resp = _ensure_db()
    if not ok:
        return resp

    try:
        with engine.connect() as conn:
            # Book statistics
            book_result = conn.execute(text("SELECT COUNT(*) as total_books FROM books"))
            available_result = conn.execute(text("SELECT COUNT(*) as available_books FROM books WHERE available = true"))
            
            # Note statistics for this user
            note_result = conn.execute(
                text("SELECT COUNT(*) as user_notes FROM notes WHERE user_id = :user_id"),
                {"user_id": request.user["user_id"]}
            )

            stats = {
                "user": request.user["username"],
                "books": {
                    "total": book_result.scalar() or 0,
                    "available": available_result.scalar() or 0
                },
                "notes": {
                    "user_notes": note_result.scalar() or 0
                },
                "timestamp": datetime.now().isoformat()
            }

        return jsonify(stats=stats), 200

    except SQLAlchemyError as e:
        return jsonify(error="Database error", details=str(e)), 500


# Error Handlers 
@app.errorhandler(404)
def not_found(error):
    return jsonify(error="Endpoint not found"), 404


@app.errorhandler(500)
def internal_error(error):
    return jsonify(error="Internal server error"), 500


# Application Startup 
if __name__ == "__main__":
    print("=" * 60)
    print("SECURE LIBRARY BACKEND - HUMAN SECURITY SYSTEM")
    print("=" * 60)
    print(f"Server URL: http://127.0.0.1:5000")
    print(f"CORS Origin: http://localhost:5500")
    print(f"Keycloak URL: {KEYCLOAK_BASE_URL}")
    print(f"Database: {'Connected' if engine else 'Not connected'}")
    print("-" * 60)
    print("Available Endpoints:")
    print("  GET    /public         - Public endpoint")
    print("  GET    /me             - Get user info")
    print("  GET    /health         - Health check")
    print("  GET    /stats          - System statistics")
    print("  GET    /books          - List books")
    print("  POST   /books          - Create book")
    print("  DELETE /books/:id      - Delete book")
    print("  GET    /notes          - List user notes")
    print("  POST   /notes          - Create note")
    print("  DELETE /notes/:id      - Delete note")
    print("=" * 60)
    
    app.run(host="127.0.0.1", port=5000, debug=True)