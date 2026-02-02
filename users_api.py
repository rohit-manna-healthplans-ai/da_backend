"""Users API (RBAC).

Phase 7 additions:
 - GET /api/users/<user_key> (detail; scoped)
 - GET /api/users/<user_key>/analysis (KPIs + charts for that user)

Notes:
 - Historically, routes used <company_username> (email) as the identifier.
 - In production, users are uniquely identified by their device/user MAC id, stored as users._id.
 - To avoid "merged" analysis when emails are duplicated/missing/renamed, we now accept either:
     * an email address, OR
     * a MAC id / user id (users._id)
   in the <user_key> path parameter.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
import re
from typing import Any, Dict, List, Optional

from flask import Blueprint, jsonify, request, g

from auth import hash_password
from db import users, logs as logs_col, screenshots as shots_col
from rbac import (
    require_dashboard_access,
    require_csuite,
    scope_filter_for_users,
    ROLE_DEPT_MEMBER,
)

users_api = Blueprint("users_api", __name__)


def ok(data=None, status: int = 200):
    return jsonify({"ok": True, "data": data}), status


def err(msg: str, status: int = 400):
    return jsonify({"ok": False, "error": msg}), status


def _email_ok(email: str) -> bool:
    return bool(re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email or ""))


def _norm_email(email: str) -> str:
    return (email or "").strip().lower()


def _public_user(u: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "_id": str(u.get("_id")),
        "user_mac_id": u.get("user_mac_id") or str(u.get("_id")),
        "company_username": u.get("company_username"),
        "company_username_norm": u.get("company_username_norm") or _norm_email(u.get("company_username")),
        "full_name": u.get("full_name") or u.get("name"),
        "contact_no": u.get("contact_no"),
        "pc_username": u.get("pc_username"),
        "department": u.get("department"),
        "role_key": (u.get("role_key") or ROLE_DEPT_MEMBER),
        "license_accepted": bool(u.get("license_accepted", False)),
        "license_version": u.get("license_version", "1.0"),
        "license_accepted_at": u.get("license_accepted_at"),
        "created_at": u.get("created_at"),
        "last_seen_at": u.get("last_seen_at"),
        "is_active": bool(u.get("is_active", True)),
    }


def parse_ymd(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except Exception:
        return None


def daterange(start: datetime, end: datetime):
    d = start
    while d <= end:
        yield d.strftime("%Y-%m-%d")
        d += timedelta(days=1)


def parse_iso(ts: str) -> Optional[datetime]:
    if not ts:
        return None
    s = str(ts).strip()
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        return datetime.fromisoformat(s)
    except Exception:
        try:
            return datetime.strptime(s[:19], "%Y-%m-%dT%H:%M:%S")
        except Exception:
            return None


def read_bucket(doc: Dict[str, Any], key: str, day: str):
    return (doc.get(key) or {}).get(day, []) or []


def read_archives(col, mac_id: str, key: str, day: str):
    # Archive document ids use pipe separators. `|` is regex alternation,
    # so we MUST escape the prefix; otherwise the query can match unrelated
    # documents and corrupt KPI calculations.
    prefix = f"{mac_id}|archive|{key}|{day}|"
    safe_prefix = re.escape(prefix)
    return col.find({"_id": {"$regex": f"^{safe_prefix}"}})


def get_range_from_request() -> (datetime, datetime, str, str):
    from_s = request.args.get("from") or request.args.get("start")
    to_s = request.args.get("to") or request.args.get("end")

    start = parse_ymd(from_s)
    end = parse_ymd(to_s)

    if not start and not end:
        now = datetime.utcnow()
        start = end = datetime(now.year, now.month, now.day)
    elif start and not end:
        end = start
    elif end and not start:
        start = end

    return start, end, (from_s or start.strftime("%Y-%m-%d")), (to_s or end.strftime("%Y-%m-%d"))


def compute_active_minutes(times: List[datetime], gap_minutes: int = 5) -> int:
    if not times:
        return 0
    times.sort()
    total_seconds = len(times) * 60  # base 1 minute per event
    for i in range(1, len(times)):
        dt = (times[i] - times[i - 1]).total_seconds()
        if 0 < dt <= gap_minutes * 60:
            total_seconds += dt
    return int(total_seconds // 60)


def _looks_like_email(s: str) -> bool:
    s = (s or "").strip()
    return "@" in s and "." in s


def _get_user_scoped_by_key(user_key: str, identity: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Resolve a user either by email (company_username) or by unique mac id.

    Why: analysis/logs/screenshots must not merge when emails are duplicated/mis-normalized.
    The system's true unique key is the user's mac id stored in users._id.

    user_key can be:
    - company email (preferred in older UI)
    - user_mac_id / _id (preferred)
    """

    key = (user_key or "").strip()
    u = None

    if _looks_like_email(key):
        email = _norm_email(key)
        u = users.find_one({"company_username_norm": email})
        if not u:
            u = users.find_one({"company_username": email})
    else:
        # Treat as mac id / unique id
        u = users.find_one({"_id": key})
        if not u:
            u = users.find_one({"user_mac_id": key})

    if not u:
        return None

    # Scope check (same rules as list)
    q = scope_filter_for_users(identity)
    scoped = users.find_one({**q, "_id": u["_id"]}, {"_id": 1})
    if not scoped:
        return None
    return u


@users_api.get("/api/users")
@require_dashboard_access()
def list_users_route():
    identity = getattr(g, "identity", {}) or {}
    department_override = (request.args.get("department") or "").strip() or None
    q = scope_filter_for_users(identity, department_override=department_override)

    projection = {
        "password_hash": 0,
        "password_salt": 0,
        "password_iter": 0,
        "password": 0,
        "password_type": 0,
        "reset_token": 0,
    }

    out: List[Dict[str, Any]] = []
    for u in users.find(q, projection).sort("created_at", -1):
        out.append(_public_user(u))
    return ok(out)


@users_api.get("/api/users/<user_key>")
@require_dashboard_access()
def get_user_detail(user_key: str):
    identity = getattr(g, "identity", {}) or {}
    u = _get_user_scoped_by_key(user_key, identity)
    if not u:
        return err("user not found (or not in your scope)", 404)
    return ok(_public_user(u))


@users_api.get("/api/users/<user_key>/analysis")
@require_dashboard_access()
def get_user_analysis(user_key: str):
    identity = getattr(g, "identity", {}) or {}
    u = _get_user_scoped_by_key(user_key, identity)
    if not u:
        return err("user not found (or not in your scope)", 404)

    mac = str(u.get("_id"))
    start, end, from_s, to_s = get_range_from_request()
    days = list(daterange(start, end))

    apps = Counter()
    cats = Counter()
    logs_count = 0
    shots_count = 0
    last_updated: Optional[datetime] = None

    per_day_logs = {d: 0 for d in days}
    per_day_shots = {d: 0 for d in days}
    per_day_active_secs = {d: 0 for d in days}
    times_by_day: Dict[str, List[datetime]] = defaultdict(list)

    # Logs
    doc = logs_col.find_one({"_id": mac}) or {}
    for day in days:
        events = list(read_bucket(doc, "logs", day))
        for a in read_archives(logs_col, mac, "logs", day):
            events.extend(read_bucket(a, "logs", day))

        for e in events:
            if not isinstance(e, dict):
                continue

            # IMPORTANT:
            # Some historical data contains events stored under one document (mac)
            # but the embedded event claims a different `user_mac_id`.
            # The user-facing Logs/Screenshots tabs correctly filter these out,
            # so the KPI header must apply the same rule; otherwise totals differ.
            claimed = e.get("user_mac_id") or mac
            if claimed != mac:
                continue

            logs_count += 1
            per_day_logs[day] += 1
            apps[str(e.get("application") or "(unknown)")] += 1
            cats[str(e.get("category") or "(unknown)")] += 1

            dt = parse_iso(e.get("ts") or "")
            if dt:
                times_by_day[day].append(dt)
                if (last_updated is None) or (dt > last_updated):
                    last_updated = dt

    # Screenshots
    sdoc = shots_col.find_one({"_id": mac}) or {}
    for day in days:
        items = list(read_bucket(sdoc, "screenshots", day))
        for a in read_archives(shots_col, mac, "screenshots", day):
            items.extend(read_bucket(a, "screenshots", day))

        for s in items:
            if not isinstance(s, dict):
                continue

            claimed = s.get("user_mac_id") or mac
            if claimed != mac:
                continue

            shots_count += 1
            per_day_shots[day] += 1
            dt = parse_iso(s.get("ts") or "")
            if dt and ((last_updated is None) or (dt > last_updated)):
                last_updated = dt

    # Active time per day (same heuristic as insights)
    for d in days:
        per_day_active_secs[d] = compute_active_minutes(times_by_day[d]) * 60

    return ok({
        "range": {"from": from_s, "to": to_s},
        "kpis": {
            "logs": logs_count,
            "screenshots": shots_count,
            "total_apps": len([k for k, v in apps.items() if v > 0 and k != "(unknown)"]) or len(apps),
            "most_used_app": apps.most_common(1)[0][0] if apps else None,
            "top_category": cats.most_common(1)[0][0] if cats else None,
            "total_active_minutes": int(sum(per_day_active_secs.values()) // 60),
            "last_updated": last_updated.isoformat() if last_updated else None,
        },
        "charts": {
            "activity_over_time": {
                "labels": days,
                "series": [{"name": "Active Minutes", "data": [int(per_day_active_secs[d] // 60) for d in days]}],
            },
            "logs_over_time": {
                "labels": days,
                "series": [{"name": "Logs", "data": [int(per_day_logs[d]) for d in days]}],
            },
            "screenshots_over_time": {
                "labels": days,
                "series": [{"name": "Screenshots", "data": [int(per_day_shots[d]) for d in days]}],
            },
            "top_apps": {"items": [{"name": k, "count": v} for k, v in apps.most_common(10)]},
            "top_categories": {"items": [{"name": k, "count": v} for k, v in cats.most_common(10)]},
        }
    })


@users_api.post("/api/users")
@require_csuite()
def create_user_route():
    body = request.get_json(silent=True) or {}

    user_mac_id = (body.get("user_mac_id") or "").strip()
    company_username = _norm_email(body.get("company_username") or body.get("email"))
    password = body.get("password") or ""

    department = (body.get("department") or "").strip()
    pc_username = (body.get("pc_username") or "").strip()
    role_key = (body.get("role_key") or ROLE_DEPT_MEMBER).strip().upper()

    full_name = (body.get("full_name") or body.get("name") or "").strip()
    contact_no = (body.get("contact_no") or "").strip()

    license_accepted = bool(body.get("license_accepted", False))
    license_version = (body.get("license_version") or "1.0").strip()

    if not user_mac_id or not company_username or not password:
        return err("user_mac_id, company_username (email) and password are required", 400)
    if not _email_ok(company_username):
        return err("invalid email format", 400)

    if users.find_one({"company_username_norm": company_username}) or users.find_one({"company_username": company_username}):
        return err("email already registered", 409)
    if users.find_one({"_id": user_mac_id}):
        return err("device (mac) already registered", 409)

    now = datetime.utcnow()
    pw_hash, pw_salt, pw_iter = hash_password(password)

    doc = {
        "_id": user_mac_id,
        "user_mac_id": user_mac_id,
        "company_username": company_username,
        "company_username_norm": company_username,
        "full_name": full_name or None,
        "contact_no": contact_no or None,
        "department": department,
        "pc_username": pc_username,
        "role_key": role_key,
        "license_accepted": license_accepted,
        "license_accepted_at": now if license_accepted else None,
        "license_version": license_version,
        "created_at": now,
        "last_seen_at": now,
        "is_active": True,
        "password_hash": pw_hash,
        "password_salt": pw_salt,
        "password_iter": pw_iter,
        "password_updated_at": now,
    }

    users.insert_one(doc)
    return ok({"user_mac_id": user_mac_id, "company_username": company_username}, 201)


@users_api.route("/api/users/<company_username>", methods=["PUT", "PATCH"])
@require_csuite()
def update_user_route(company_username: str):
    company_username = _norm_email(company_username)
    body = request.get_json(silent=True) or {}

    u = users.find_one({"company_username_norm": company_username})
    if not u:
        u = users.find_one({"company_username": company_username})
    if not u:
        return err("user not found", 404)

    update: Dict[str, Any] = {}
    unset: Dict[str, Any] = {}

    for key in ["department", "pc_username", "role_key", "is_active", "license_version"]:
        if key in body:
            if key == "role_key" and body.get(key):
                update[key] = str(body[key]).strip().upper()
            else:
                update[key] = body.get(key)

    if "full_name" in body:
        update["full_name"] = (body.get("full_name") or "").strip() or None
    if "name" in body and "full_name" not in update:
        update["full_name"] = (body.get("name") or "").strip() or None
    if "contact_no" in body:
        update["contact_no"] = (body.get("contact_no") or "").strip() or None

    if "license_accepted" in body:
        update["license_accepted"] = bool(body.get("license_accepted"))
        update["license_accepted_at"] = datetime.utcnow() if update["license_accepted"] else None

    if body.get("password"):
        pw_hash, pw_salt, pw_iter = hash_password(body["password"])
        update["password_hash"] = pw_hash
        update["password_salt"] = pw_salt
        update["password_iter"] = pw_iter
        update["password_updated_at"] = datetime.utcnow()

        unset["password"] = ""
        unset["password_type"] = ""

    if body.get("company_username"):
        new_email = _norm_email(body["company_username"])
        if not _email_ok(new_email):
            return err("invalid email format", 400)
        update["company_username"] = new_email
        update["company_username_norm"] = new_email

    if not update and not unset:
        return ok({"message": "no changes"}, 200)

    ops: Dict[str, Any] = {}
    if update:
        ops["$set"] = update
    if unset:
        ops["$unset"] = unset

    users.update_one({"_id": u["_id"]}, ops)
    fresh = users.find_one({"_id": u["_id"]})
    return ok(_public_user(fresh or u))
