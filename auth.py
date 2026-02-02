from datetime import datetime, timedelta
import base64
import hashlib
import hmac
import os
import jwt
from bson import ObjectId

from config import JWT_SECRET
from db import users

DEFAULT_ITER = 210000


def _b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("utf-8")


def _b64d(s: str) -> bytes:
    return base64.b64decode((s or "").encode("utf-8"))


def hash_password(pw: str, iters: int = DEFAULT_ITER):
    """
    Returns (password_hash_b64, password_salt_b64, password_iter)
    """
    if pw is None:
        pw = ""
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, int(iters), dklen=32)
    return _b64e(dk), _b64e(salt), int(iters)


def verify_password(pw: str, pw_hash_b64: str, pw_salt_b64: str, pw_iter: int) -> bool:
    if pw is None:
        pw = ""
    try:
        salt = _b64d(pw_salt_b64)
        iters = int(pw_iter or DEFAULT_ITER)
        expected = _b64d(pw_hash_b64)
        dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters, dklen=32)
        return hmac.compare_digest(dk, expected)
    except Exception:
        return False


def issue_token(
    user_id: str,
    role_key: str = "DEPARTMENT_MEMBER",
    *,
    department: str = None,
    company_username: str = None,
    mac_id: str = None,
):
    """Issue a JWT for portal/dashboard authentication.

    We keep claims minimal but include department/email so RBAC can work
    without an extra DB read on every request.
    """
    payload = {
        "sub": str(user_id),  # ObjectId string OR MAC string
        "role_key": (role_key or "DEPARTMENT_MEMBER").strip().upper(),
        "department": department,
        "company_username": (company_username or None),
        "mac_id": mac_id,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(days=7),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def jwt_verify(token: str):
    return jwt.decode(token, JWT_SECRET, algorithms=["HS256"])


def _find_user_by_id(user_id: str):
    if user_id is None:
        return None
    s = str(user_id).strip()

    # ObjectId support (24-hex)
    if len(s) == 24:
        try:
            u = users.find_one({"_id": ObjectId(s)})
            if u:
                return u
        except Exception:
            pass

    return users.find_one({"_id": s})


def get_user_public(user_id: str):
    user = _find_user_by_id(user_id)
    if not user:
        return None

    email = user.get("company_username")
    email_norm = user.get("company_username_norm") or (email.lower() if email else None)

    return {
        "_id": str(user.get("_id")),
        "user_mac_id": user.get("user_mac_id") or str(user.get("_id")),
        "company_username": email,
        "company_username_norm": email_norm,

        # Human fields
        "full_name": user.get("full_name") or user.get("name"),
        "name": user.get("name") or user.get("full_name"),
        "contact_no": user.get("contact_no"),

        # aliases to keep old code safe
        "username": email,
        "role": user.get("role_key", "DEPARTMENT_MEMBER"),

        "pc_username": user.get("pc_username"),
        "department": user.get("department"),
        "role_key": user.get("role_key", "DEPARTMENT_MEMBER"),

        "license_accepted": bool(user.get("license_accepted", False)),
        "license_version": user.get("license_version", "1.0"),
        "license_accepted_at": user.get("license_accepted_at"),

        "created_at": user.get("created_at"),
        "last_seen_at": user.get("last_seen_at"),

        "is_active": bool(user.get("is_active", True)),
    }
