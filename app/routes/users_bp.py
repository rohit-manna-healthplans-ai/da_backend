from flask import Blueprint, jsonify, request

from app.auth_jwt import require_auth
from app.config import COL_USERS
from app.db import get_db, utc_now_iso
from app.rbac import list_users_filter_query, load_user_by_id, role_from_user, can_access_user_mac_id, actor_user_mac_id
from app.serializers import user_public
from app.user_activity import enrich_user_agent_presence, enrich_users_agent_presence
import bcrypt

bp = Blueprint("users", __name__, url_prefix="/api/users")


def _hash_pw(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _actor(request):
    uid = getattr(request, "jwt_payload", {}).get("sub")
    return load_user_by_id(uid) if uid else None


def _find_user(identifier: str):
    if not identifier:
        return None
    db = get_db()
    raw = identifier.strip()
    low = raw.lower()
    return db[COL_USERS].find_one(
        {
            "$or": [
                {"company_username_norm": low},
                {"company_username": raw},
                {"_id": raw},
                {"user_mac_id": raw},
            ]
        }
    )


@bp.get("")
@require_auth
def list_users():
    actor = _actor(request)
    if not actor:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    r = role_from_user(actor)
    if r == "DEPARTMENT_MEMBER":
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    q = list_users_filter_query(actor)
    if q.get("_id") == {"$exists": False}:
        return jsonify({"ok": True, "data": []})

    db = get_db()
    cur = db[COL_USERS].find(q).sort([("full_name", 1), ("company_username_norm", 1)])
    items = enrich_users_agent_presence(db, [user_public(d) for d in cur])
    return jsonify({"ok": True, "data": items})


@bp.get("/me")
@require_auth
def get_me():
    actor = _actor(request)
    if not actor:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    db = get_db()
    data = enrich_user_agent_presence(db, user_public(actor))
    return jsonify({"ok": True, "data": data})


@bp.get("/<path:identifier>")
@require_auth
def get_user(identifier: str):
    actor = _actor(request)
    if not actor:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401
    r = role_from_user(actor)

    u = _find_user(identifier)
    if not u:
        return jsonify({"ok": False, "error": "User not found"}), 404

    uid = str(u.get("user_mac_id") or u.get("_id"))
    actor_uid = actor_user_mac_id(actor)

    if r == "DEPARTMENT_MEMBER":
        if not (actor_uid and uid == actor_uid):
            return jsonify({"ok": False, "error": "Forbidden"}), 403
    elif not can_access_user_mac_id(actor, uid):
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    db = get_db()
    data = enrich_user_agent_presence(db, user_public(u))
    return jsonify({"ok": True, "data": data})


@bp.post("")
@require_auth
def create_user():
    actor = _actor(request)
    if not actor or role_from_user(actor) != "C_SUITE":
        return jsonify({"ok": False, "error": "Only C-Suite can create users"}), 403

    body = request.get_json(force=True, silent=True) or {}
    user_mac_id = (body.get("user_mac_id") or "").strip()
    email = (body.get("company_username") or body.get("email") or "").strip()
    password = body.get("password") or ""
    if not user_mac_id or not email or not password:
        return jsonify({"ok": False, "error": "user_mac_id, company_username, password required"}), 400

    db = get_db()
    email_norm = email.lower()
    if db[COL_USERS].find_one({"company_username_norm": email_norm}):
        return jsonify({"ok": False, "error": "Email already exists"}), 409
    if db[COL_USERS].find_one({"$or": [{"_id": user_mac_id}, {"user_mac_id": user_mac_id}]}):
        return jsonify({"ok": False, "error": "user_mac_id already exists"}), 409

    role_key = str(body.get("role_key") or "DEPARTMENT_MEMBER").upper()
    doc = {
        "_id": user_mac_id,
        "user_mac_id": user_mac_id,
        "pc_username": body.get("pc_username") or "",
        "company_username_norm": email_norm,
        "company_username": email,
        "full_name": body.get("full_name"),
        "contact_no": body.get("contact_no"),
        "role_key": role_key,
        "department": body.get("department") or None,
        "license_accepted": bool(body.get("license_accepted", True)),
        "license_version": body.get("license_version"),
        "license_accepted_at": utc_now_iso(),
        "last_seen_at": utc_now_iso(),
        "created_at": utc_now_iso(),
        "password_hash": _hash_pw(password),
        "is_active": bool(body.get("is_active", True)),
    }
    db[COL_USERS].insert_one(doc)
    return jsonify({"ok": True, "data": enrich_user_agent_presence(db, user_public(doc))})


@bp.patch("/<path:company_username>")
@require_auth
def patch_user(company_username: str):
    actor = _actor(request)
    if not actor or role_from_user(actor) != "C_SUITE":
        return jsonify({"ok": False, "error": "Only C-Suite can update users"}), 403

    u = _find_user(company_username)
    if not u:
        return jsonify({"ok": False, "error": "User not found"}), 404

    body = request.get_json(force=True, silent=True) or {}
    updates = {}
    for k in ("full_name", "contact_no", "pc_username", "department", "role_key", "is_active"):
        if k in body:
            updates[k] = body[k]
    if body.get("password"):
        updates["password_hash"] = _hash_pw(body["password"])
    db = get_db()
    if not updates:
        return jsonify({"ok": True, "data": enrich_user_agent_presence(db, user_public(u))})

    updates["updated_at"] = utc_now_iso()
    db[COL_USERS].update_one({"_id": u["_id"]}, {"$set": updates})
    fresh = db[COL_USERS].find_one({"_id": u["_id"]})
    return jsonify({"ok": True, "data": enrich_user_agent_presence(db, user_public(fresh))})
