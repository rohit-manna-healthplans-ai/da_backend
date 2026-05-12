import bcrypt
from flask import Blueprint, jsonify, request

from app.auth_jwt import issue_token, require_auth, decode_token
from app.config import COL_USERS, OPEN_REGISTRATION
from app.db import get_db, utc_now_iso
from app.serializers import user_public
from app.user_activity import enrich_user_agent_presence

bp = Blueprint("auth", __name__, url_prefix="/api/auth")


def _find_login_user(email: str):
    db = get_db()
    e = (email or "").strip().lower()
    if not e:
        return None
    return db[COL_USERS].find_one({"company_username_norm": e})


def _hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _check_pw(password: str, pw_hash: str) -> bool:
    if not pw_hash:
        return False
    try:
        return bcrypt.checkpw(password.encode("utf-8"), pw_hash.encode("utf-8"))
    except Exception:
        return False


@bp.post("/login")
def login():
    body = request.get_json(force=True, silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""
    if not email or not password:
        return jsonify({"ok": False, "error": "email and password required"}), 400

    u = _find_login_user(email)
    if not u or not _check_pw(password, u.get("password_hash") or ""):
        return jsonify({"ok": False, "error": "Invalid credentials"}), 401

    if u.get("is_active") is False:
        return jsonify({"ok": False, "error": "Account is disabled"}), 403

    uid = str(u.get("user_mac_id") or u.get("_id") or "")
    if not uid:
        return jsonify({"ok": False, "error": "User record missing device id"}), 500

    token = issue_token({"sub": uid, "email": u.get("company_username_norm") or email})
    return jsonify({"ok": True, "data": {"token": token, "access_token": token, "profile": user_public(u)}})


@bp.get("/me")
@require_auth
def me():
    payload = getattr(request, "jwt_payload", {}) or {}
    uid = payload.get("sub")
    db = get_db()
    u = db[COL_USERS].find_one({"$or": [{"_id": uid}, {"user_mac_id": uid}]})
    if not u:
        return jsonify({"ok": False, "error": "User not found"}), 404
    data = enrich_user_agent_presence(db, user_public(u))
    return jsonify({"ok": True, "data": data})


@bp.post("/register")
def register():
    body = request.get_json(force=True, silent=True) or {}
    email = (body.get("email") or body.get("company_username") or "").strip().lower()
    password = body.get("password") or ""
    role = str(body.get("role") or body.get("role_key") or "DEPARTMENT_HEAD").upper()
    full_name = body.get("full_name")
    department = body.get("department")
    license_accepted = bool(body.get("licenseAccepted") or body.get("license_accepted"))

    if not email or not password:
        return jsonify({"ok": False, "error": "email and password required"}), 400
    if role == "DEPARTMENT_HEAD" and not (department and str(department).strip()):
        return jsonify({"ok": False, "error": "department required for department head"}), 400

    db = get_db()
    if db[COL_USERS].find_one({"company_username_norm": email}):
        return jsonify({"ok": False, "error": "Email already registered"}), 409

    # First user in DB: always allow signup without token.
    # After that: need C-Suite JWT, OR OPEN_REGISTRATION=true in env (Render dashboard).
    count = db[COL_USERS].count_documents({})
    if count > 0 and not OPEN_REGISTRATION:
        auth = request.headers.get("Authorization") or ""
        if not auth.startswith("Bearer "):
            return jsonify(
                {
                    "ok": False,
                    "error": (
                        "Registration is closed: log in as C-Suite and add users from the dashboard, "
                        "or set environment variable OPEN_REGISTRATION=true on the server (staging only)."
                    ),
                }
            ), 403
        pl = decode_token(auth.split(" ", 1)[1].strip())
        if not pl:
            return jsonify({"ok": False, "error": "Invalid or expired token"}), 401
        actor = db[COL_USERS].find_one({"$or": [{"_id": pl.get("sub")}, {"user_mac_id": pl.get("sub")}]})
        if not actor or str(actor.get("role_key") or "").upper() != "C_SUITE":
            return jsonify({"ok": False, "error": "Only C-Suite can create users"}), 403

    import uuid

    user_mac_id = body.get("user_mac_id") or str(uuid.uuid4())
    doc = {
        "_id": user_mac_id,
        "user_mac_id": user_mac_id,
        "pc_username": body.get("pc_username") or "",
        "company_username_norm": email,
        "company_username": body.get("company_username") or email,
        "full_name": full_name,
        "role_key": role,
        "department": (department or None) if role != "C_SUITE" else None,
        "license_accepted": license_accepted,
        "license_version": body.get("license_version"),
        "license_accepted_at": utc_now_iso() if license_accepted else None,
        "last_seen_at": utc_now_iso(),
        "created_at": utc_now_iso(),
        "password_hash": _hash_pw(password),
        "is_active": True,
    }
    db[COL_USERS].insert_one(doc)
    return jsonify({"ok": True, "data": user_public(doc)})


@bp.post("/forgot-password")
def forgot_password():
    body = request.get_json(force=True, silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    new_password = body.get("new_password") or ""
    if not email or len(new_password) < 4:
        return jsonify({"ok": False, "error": "email and new_password (min 4) required"}), 400

    db = get_db()
    u = db[COL_USERS].find_one({"company_username_norm": email})
    if not u:
        return jsonify({"ok": False, "error": "User not found"}), 404
    if u.get("is_active") is False:
        return jsonify({"ok": False, "error": "Account is disabled"}), 403

    db[COL_USERS].update_one(
        {"_id": u["_id"]},
        {"$set": {"password_hash": _hash_pw(new_password), "updated_at": utc_now_iso()}},
    )
    return jsonify({"ok": True, "data": {"message": "Password updated"}})
