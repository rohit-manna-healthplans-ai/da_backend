from flask import Blueprint, jsonify, request

from app.auth_jwt import require_auth
from app.config import COL_LOGS, COL_USERS
from app.db import get_db
from app.rbac import can_access_user_mac_id, load_user_by_id
from app.serializers import log_row
from app.time_range import range_iso_strings

bp = Blueprint("logs", __name__, url_prefix="/api/logs")

# Only fields the dashboard needs — less data over the wire & faster BSON decode
_LOG_FIELDS = {
    "_id": 1,
    "log_id": 1,
    "user_mac_id": 1,
    "pc_username": 1,
    "ts": 1,
    "category": 1,
    "details": 1,
    "application": 1,
    "window_title": 1,
    "operation": 1,
    "screenshot_id": 1,
    "created_at": 1,
}


def _actor(request):
    uid = getattr(request, "jwt_payload", {}).get("sub")
    return load_user_by_id(uid) if uid else None


@bp.get("")
@require_auth
def list_logs():
    actor = _actor(request)
    if not actor:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    user_mac_id = (request.args.get("user_mac_id") or "").strip()
    company_username = (request.args.get("company_username") or "").strip()
    from_d = (request.args.get("from") or "").strip()
    to_d = (request.args.get("to") or "").strip()

    if not from_d or not to_d:
        return jsonify({"ok": False, "error": "from and to (YYYY-MM-DD) required"}), 400

    try:
        start_iso, end_iso = range_iso_strings(from_d, to_d)
    except Exception as e:
        return jsonify({"ok": False, "error": f"Invalid date range: {e}"}), 400

    db = get_db()

    # Resolve user id from email if needed (fast path prefers user_mac_id)
    if not user_mac_id and company_username:
        low = company_username.lower()
        u = db[COL_USERS].find_one(
            {"$or": [{"company_username_norm": low}, {"company_username": company_username}]},
            {"_id": 1, "user_mac_id": 1},
        )
        if u:
            user_mac_id = str(u.get("user_mac_id") or u.get("_id") or "")

    if not user_mac_id:
        return jsonify({"ok": False, "error": "user_mac_id (or company_username) required"}), 400

    if not can_access_user_mac_id(actor, user_mac_id):
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    try:
        page = max(1, int(request.args.get("page") or 1))
    except ValueError:
        page = 1
    try:
        limit = min(500, max(1, int(request.args.get("limit") or 100)))
    except ValueError:
        limit = 100

    # Primary: index-friendly range on ts (ISO string compare)
    filt: dict = {
        "user_mac_id": user_mac_id,
        "ts": {"$gte": start_iso, "$lte": end_iso},
    }

    col = db[COL_LOGS]
    total = col.count_documents(filt)
    skip = (page - 1) * limit

    cur = col.find(filt, _LOG_FIELDS).sort("ts", -1).skip(skip).limit(limit)
    # hint matches compound index (user_mac_id, ts DESC)
    try:
        cur = cur.hint([("user_mac_id", 1), ("ts", -1)])
    except Exception:
        pass

    items = [log_row(d) for d in cur]
    return jsonify(
        {
            "ok": True,
            "data": {"items": items, "total": total, "page": page, "limit": limit},
        }
    )
