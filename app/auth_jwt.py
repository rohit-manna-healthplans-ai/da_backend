import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional

from flask import request, jsonify

from app.config import JWT_SECRET, JWT_EXPIRES_HOURS


def issue_token(claims: Dict[str, Any]) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        **claims,
        "iat": now,
        "exp": now + timedelta(hours=JWT_EXPIRES_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    except jwt.PyJWTError:
        return None


def require_auth(f: Callable) -> Callable:
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization") or ""
        if not auth.startswith("Bearer "):
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        token = auth.split(" ", 1)[1].strip()
        payload = decode_token(token)
        if not payload:
            return jsonify({"ok": False, "error": "Invalid token"}), 401
        request.jwt_payload = payload
        return f(*args, **kwargs)

    return decorated
