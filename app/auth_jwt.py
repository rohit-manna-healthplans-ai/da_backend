import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Any, Callable, Dict, Optional

from flask import request, jsonify

from app.config import COL_USERS, JWT_SECRET, JWT_EXPIRES_HOURS
from app.db import get_db


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


def load_user_by_jwt_sub(sub: str):
    """Resolve users collection row from JWT `sub` (device / user id)."""
    if not sub:
        return None
    db = get_db()
    return db[COL_USERS].find_one({"$or": [{"_id": sub}, {"user_mac_id": sub}]})


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
        u = load_user_by_jwt_sub(payload.get("sub") or "")
        if not u:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401
        if u.get("is_active") is False:
            return jsonify({"ok": False, "error": "Account is disabled"}), 403
        request.jwt_payload = payload
        return f(*args, **kwargs)

    return decorated
