from flask import Blueprint, jsonify, request

from app.auth_jwt import require_auth
from app.config import COL_DEPARTMENTS
from app.db import get_db, utc_now_iso
from app.rbac import load_user_by_id, role_from_user
from app.serializers import department_public

bp = Blueprint("departments", __name__, url_prefix="/api/departments")


def _actor(request):
    uid = getattr(request, "jwt_payload", {}).get("sub")
    return load_user_by_id(uid) if uid else None


@bp.get("")
@require_auth
def list_departments():
    actor = _actor(request)
    if not actor:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    db = get_db()
    cur = db[COL_DEPARTMENTS].find({"is_active": {"$ne": False}}).sort("department_name", 1)
    items = [department_public(d) for d in cur]
    return jsonify({"ok": True, "data": items})


@bp.post("")
@require_auth
def create_department():
    actor = _actor(request)
    if not actor or role_from_user(actor) != "C_SUITE":
        return jsonify({"ok": False, "error": "Only C-Suite can create departments"}), 403

    body = request.get_json(force=True, silent=True) or {}
    name = (body.get("name") or body.get("department_name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400

    code = (body.get("department_code") or body.get("code") or name).strip().upper().replace(" ", "_")
    db = get_db()
    if db[COL_DEPARTMENTS].find_one({"$or": [{"_id": code}, {"department_code": code}]}):
        return jsonify({"ok": False, "error": "Department already exists"}), 409

    now = utc_now_iso()
    doc = {
        "_id": code,
        "department_name": name,
        "department_code": code,
        "is_active": True,
        "created_at": now,
        "updated_at": now,
    }
    db[COL_DEPARTMENTS].insert_one(doc)
    return jsonify({"ok": True, "data": department_public(doc)})
