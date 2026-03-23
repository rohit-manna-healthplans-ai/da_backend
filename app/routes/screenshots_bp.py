from flask import Blueprint, jsonify, request
from bson import ObjectId

from app.auth_jwt import require_auth
from app.azure_blob import azure_credentials_configured, build_read_sas_url, resolve_blob_location
from app.config import COL_SCREENSHOTS, COL_USERS
from app.db import get_db
from app.rbac import can_access_user_mac_id, load_user_by_id
from app.serializers import screenshot_row
from app.time_range import range_iso_strings

bp = Blueprint("screenshots", __name__, url_prefix="/api/screenshots")

_SHOT_FIELDS = {
    "_id": 1,
    "screenshot_id": 1,
    "user_mac_id": 1,
    "pc_username": 1,
    "ts": 1,
    "application": 1,
    "window_title": 1,
    "operation": 1,
    "file_path": 1,
    "screenshot_url": 1,
    "created_at": 1,
}


def _actor(request):
    uid = getattr(request, "jwt_payload", {}).get("sub")
    return load_user_by_id(uid) if uid else None


def _find_screenshot(db, shot_id: str):
    shot_id = (shot_id or "").strip()
    if not shot_id:
        return None
    clauses = [{"screenshot_id": shot_id}]
    if ObjectId.is_valid(shot_id):
        try:
            clauses.append({"_id": ObjectId(shot_id)})
        except Exception:
            pass
    return db[COL_SCREENSHOTS].find_one({"$or": clauses})


@bp.get("")
@require_auth
def list_screenshots():
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
        limit = min(500, max(1, int(request.args.get("limit") or 50)))
    except ValueError:
        limit = 50

    filt: dict = {
        "user_mac_id": user_mac_id,
        "ts": {"$gte": start_iso, "$lte": end_iso},
    }

    col = db[COL_SCREENSHOTS]
    total = col.count_documents(filt)
    skip = (page - 1) * limit

    cur = col.find(filt, _SHOT_FIELDS).sort("ts", -1).skip(skip).limit(limit)
    try:
        cur = cur.hint([("user_mac_id", 1), ("ts", -1)])
    except Exception:
        pass

    items = [screenshot_row(d) for d in cur]
    return jsonify(
        {
            "ok": True,
            "data": {"items": items, "total": total, "page": page, "limit": limit},
        }
    )


@bp.get("/<shot_id>/sas-url")
@require_auth
def get_screenshot_sas_url(shot_id: str):
    """Return a time-limited read SAS URL for a private Azure blob (screenshot)."""
    actor = _actor(request)
    if not actor:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    if not azure_credentials_configured():
        return jsonify(
            {
                "ok": False,
                "error": "Azure Blob Storage is not configured (set AZURE_STORAGE_ACCOUNT_NAME and AZURE_STORAGE_ACCOUNT_KEY).",
            }
        ), 503

    db = get_db()
    doc = _find_screenshot(db, shot_id)
    if not doc:
        return jsonify({"ok": False, "error": "Screenshot not found"}), 404

    target_uid = str(doc.get("user_mac_id") or "")
    if not can_access_user_mac_id(actor, target_uid):
        return jsonify({"ok": False, "error": "Forbidden"}), 403

    loc = resolve_blob_location(doc)
    if not loc:
        return jsonify(
            {
                "ok": False,
                "error": "Cannot resolve blob (set screenshot_url or file_path; AZURE_STORAGE_ACCOUNT_NAME must match the account in the URL).",
            }
        ), 400

    account_name, container_name, blob_name = loc
    try:
        url, expiry_mins = build_read_sas_url(
            account_name=account_name,
            container_name=container_name,
            blob_name=blob_name,
        )
    except RuntimeError as e:
        return jsonify({"ok": False, "error": str(e)}), 503
    except Exception as e:
        return jsonify({"ok": False, "error": f"SAS generation failed: {e!s}"}), 500

    return jsonify(
        {
            "ok": True,
            "data": {
                "url": url,
                "sas_url": url,
                "expires_in_minutes": expiry_mins,
            },
        }
    )
