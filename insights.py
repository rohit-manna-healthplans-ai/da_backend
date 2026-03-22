from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timedelta
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from flask import Blueprint, jsonify, request, g

from config import MAX_ANALYSIS_DAYS
from db import ensure_indexes, users, logs, screenshots
from rbac import require_dashboard_access, require_overview_access, ROLE_C_SUITE, ROLE_DEPT_HEAD, ROLE_DEPT_MEMBER

insights_api = Blueprint("insights_api", __name__)


def ok(data=None, status: int = 200):
    return jsonify({"ok": True, "data": data}), status


def parse_ymd(s: str) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except Exception:
        return None


def parse_iso(ts: str) -> Optional[datetime]:
    """Parse ISO-8601 timestamps coming from the plugin.

    Examples observed:
    - 2026-01-23T08:00:20.046702+00:00
    - 2026-01-23T08:00:20Z
    """
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


def daterange(start: datetime, end: datetime) -> Iterable[str]:
    d = start
    while d <= end:
        yield d.strftime("%Y-%m-%d")
        d += timedelta(days=1)


def get_range_from_request() -> Tuple[datetime, datetime, str, str]:
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

    # Production: allow years of data; cap from config to prevent abuse
    span_days = (end - start).days
    if span_days > MAX_ANALYSIS_DAYS:
        end = datetime(end.year, end.month, end.day)
        start = end - timedelta(days=MAX_ANALYSIS_DAYS - 1)
        from_s = start.strftime("%Y-%m-%d")
        to_s = end.strftime("%Y-%m-%d")

    return start, end, (from_s or start.strftime("%Y-%m-%d")), (to_s or end.strftime("%Y-%m-%d"))


def get_allowed_mac_ids(identity: Dict[str, Any]) -> List[str]:
    """Return list of user_mac_id values (_id in users collection) allowed for the caller.

    Supports optional request filters:
    - department: (c_suites only) limits returned users to that department
    - user: company username (norm or raw) OR user_mac_id to scope insights to a single selected user
    """
    role = (identity or {}).get("role_key")
    department = (identity or {}).get("department")

    # Base scope by role
    base_ids: List[str] = []
    if role == ROLE_C_SUITE:
        q: Dict[str, Any] = {}
        dep = request.args.get("department")
        if dep:
            q["department"] = dep
        base_ids = [u.get("_id") for u in users.find(q, {"_id": 1})]
    elif role == ROLE_DEPT_HEAD or role == ROLE_DEPT_MEMBER:
        if not department:
            base_ids = []
        else:
            base_ids = [u.get("_id") for u in users.find({"department": department}, {"_id": 1})]
    else:
        base_ids = []

    if not base_ids:
        return []

    # Optional single-user scoping (used by dashboard user-selection flow)
    user_key = (request.args.get("user") or "").strip()
    if user_key:
        key_norm = user_key.lower()

        # First, try interpreting as a mac id (_id)
        if user_key in base_ids:
            return [user_key]

        # Otherwise, resolve by username fields
        u = users.find_one(
            {
                "_id": {"$in": base_ids},
                "$or": [
                    {"company_username_norm": key_norm},
                    {"company_username": user_key},
                    {"company_username": key_norm},
                ],
            },
            {"_id": 1},
        )
        if not u:
            return []
        return [u.get("_id")]

    return base_ids


def user_map(mac_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    if not mac_ids:
        return {}
    docs = users.find(
        {"_id": {"$in": mac_ids}},
        {"_id": 1, "company_username": 1, "company_username_norm": 1, "full_name": 1, "department": 1, "role_key": 1},
    )
    out = {}
    for u in docs:
        out[u.get("_id")] = u
    return out


def read_bucket(doc: Dict[str, Any], key: str, day: str):
    val = doc.get(key)
    if val is None:
        return []
    if isinstance(val, list):
        # Some docs store the bucket as a flat list (no day key); cannot look up by day
        return []
    if isinstance(val, dict):
        return val.get(day, []) or []
    return []


def read_archives(col, mac_id: str, key: str, day: str):
    # Supports older archives format if you used it previously
    prefix = f"{mac_id}|archive|{key}|{day}|"
    # IMPORTANT: escape regex metacharacters ("|" etc.) so we don't match unrelated docs.
    safe_prefix = re.escape(prefix)
    return col.find({"_id": {"$regex": f"^{safe_prefix}"}})


def _aggregate_days_to_buckets(
    days: List[str], per_day_values: Dict[str, float], bucket: str
) -> Tuple[List[str], List[int]]:
    """Aggregate per-day series to week or month for large ranges. Returns (labels, values)."""
    if bucket == "week":
        buckets: Dict[str, float] = defaultdict(float)
        for d in days:
            dt = parse_ymd(d)
            if not dt:
                continue
            year, week, _ = dt.isocalendar()
            key = f"{year}-W{week:02d}"
            buckets[key] += per_day_values.get(d, 0)
        labels = sorted(buckets.keys(), key=lambda x: (int(x.split("-")[0]), int(x.split("-")[1].replace("W", ""))))
        return labels, [int(buckets[l]) for l in labels]
    if bucket == "month":
        buckets = defaultdict(float)
        for d in days:
            key = d[:7]
            buckets[key] += per_day_values.get(d, 0)
        labels = sorted(buckets.keys())
        return labels, [int(buckets[l]) for l in labels]
    return days, [int(per_day_values.get(d, 0)) for d in days]


def _fetch_archives_by_day(col, mac_id: str, key: str, days_set) -> Dict[str, List[Dict[str, Any]]]:
    """Fetch all archive docs for this user/key in one query, grouped by day. Speeds up large ranges."""
    if not days_set:
        return {}
    safe_mac = re.escape(str(mac_id))
    pattern = f"^{safe_mac}\\|archive\\|{re.escape(key)}\\|"
    cursor = col.find({"_id": {"$regex": pattern}})
    by_day: Dict[str, List[Dict[str, Any]]] = {d: [] for d in days_set}
    for doc in cursor:
        parts = (doc.get("_id") or "").split("|")
        if len(parts) >= 4:
            day = parts[3]
            if day in by_day:
                by_day[day].append(doc)
    return by_day


def iter_log_events(
    mac_ids: List[str], start: datetime, end: datetime,
    logs_archives_by_user: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None,
) -> Iterable[Dict[str, Any]]:
    if not mac_ids:
        return
    days_list = list(daterange(start, end))
    if logs_archives_by_user is None:
        days_set = set(days_list)
        logs_archives_by_user = {mac: _fetch_archives_by_day(logs, mac, "logs", days_set) for mac in mac_ids}
    for doc in logs.find({"_id": {"$in": mac_ids}}, {"logs": 1}):
        mac = doc.get("_id")
        archives_for_mac = logs_archives_by_user.get(mac, {})
        for day in days_list:
            for e in read_bucket(doc, "logs", day):
                if isinstance(e, dict):
                    um = e.get("user_mac_id")
                    if um and mac and str(um) != str(mac):
                        continue
                    yield e
            for a in archives_for_mac.get(day, []):
                for e in read_bucket(a, "logs", day):
                    if isinstance(e, dict):
                        um = e.get("user_mac_id")
                        if um and mac and str(um) != str(mac):
                            continue
                        yield e


def iter_screenshot_events(
    mac_ids: List[str], start: datetime, end: datetime,
    shots_archives_by_user: Optional[Dict[str, Dict[str, List[Dict[str, Any]]]]] = None,
) -> Iterable[Dict[str, Any]]:
    if not mac_ids:
        return
    days_list = list(daterange(start, end))
    if shots_archives_by_user is None:
        days_set = set(days_list)
        shots_archives_by_user = {mac: _fetch_archives_by_day(screenshots, mac, "screenshots", days_set) for mac in mac_ids}
    for doc in screenshots.find({"_id": {"$in": mac_ids}}, {"screenshots": 1}):
        mac = doc.get("_id")
        archives_for_mac = shots_archives_by_user.get(mac, {})
        for day in days_list:
            for s in read_bucket(doc, "screenshots", day):
                if isinstance(s, dict):
                    um = s.get("user_mac_id")
                    if um and mac and str(um) != str(mac):
                        continue
                    yield s
            for a in archives_for_mac.get(day, []):
                for s in read_bucket(a, "screenshots", day):
                    if isinstance(s, dict):
                        um = s.get("user_mac_id")
                        if um and mac and str(um) != str(mac):
                            continue
                        yield s



def _sessionize_seconds(times: List[datetime], gap_minutes: int) -> int:
    """Convert event timestamps into active seconds using sessionization.

    Session rules:
    - Sort timestamps.
    - A session continues while consecutive gaps <= gap_minutes.
    - Each session contributes at least 60 seconds so sparse activity isn't shown as 0.
    """
    if not times:
        return 0
    times = sorted(times)
    gap = gap_minutes * 60

    total = 0
    session_start = times[0]
    prev = times[0]

    for t in times[1:]:
        dt = (t - prev).total_seconds()
        if 0 <= dt <= gap:
            prev = t
            continue
        # close session
        total += max(60, int((prev - session_start).total_seconds()))
        session_start = t
        prev = t

    # close last session
    total += max(60, int((prev - session_start).total_seconds()))
    return total


def compute_active_minutes(events_by_user: Dict[str, List[datetime]], gap_minutes: int = 5) -> int:
    """Compute total active minutes for the selected scope.

    Fix: previously we added 1 minute per event + short gaps, which inflated totals.
    Now we sessionize event timestamps and sum session durations.
    """
    total_seconds = 0
    for _mac, times in events_by_user.items():
        total_seconds += _sessionize_seconds(times, gap_minutes=gap_minutes)
    return int(total_seconds // 60)


# --------------------------
# Existing endpoints (kept so your Overview page keeps working)
# --------------------------

@insights_api.get("/api/insights/summary")
@require_dashboard_access()
def summary():
    identity = getattr(g, "identity", {}) or {}
    mac_ids = get_allowed_mac_ids(identity)
    start, end, from_s, to_s = get_range_from_request()

    if not mac_ids:
        return ok({"totals": {"unique_users": 0, "logs": 0, "screenshots": 0}, "range": {"from": from_s, "to": to_s}})

    total_logs = 0
    total_shots = 0

    for _e in iter_log_events(mac_ids, start, end):
        total_logs += 1
    for _s in iter_screenshot_events(mac_ids, start, end):
        total_shots += 1

    return ok({
        "totals": {"unique_users": len(set(mac_ids)), "logs": total_logs, "screenshots": total_shots},
        "range": {"from": from_s, "to": to_s},
    })


@insights_api.get("/api/insights/timeseries")
@require_dashboard_access()
def timeseries():
    identity = getattr(g, "identity", {}) or {}
    mac_ids = get_allowed_mac_ids(identity)
    start, end, from_s, to_s = get_range_from_request()

    labels = list(daterange(start, end))
    counts = {day: 0 for day in labels}

    for e in iter_log_events(mac_ids, start, end):
        dt = parse_iso(e.get("ts") or "")
        if not dt:
            continue
        day = dt.strftime("%Y-%m-%d")
        if day in counts:
            counts[day] += 1

    data = [counts[d] for d in labels]
    return ok({"labels": labels, "series": [{"name": "Logs", "data": data}]})


@insights_api.get("/api/insights/top")
@require_dashboard_access()
def top():
    identity = getattr(g, "identity", {}) or {}
    mac_ids = get_allowed_mac_ids(identity)
    start, end, from_s, to_s = get_range_from_request()

    by = (request.args.get("by") or "category").strip().lower()
    limit = max(min(int(request.args.get("limit") or 10), 50), 1)

    if not mac_ids:
        return ok({"items": []})

    c = Counter()
    for e in iter_log_events(mac_ids, start, end):
        key = e.get(by) or "(unknown)"
        c[str(key)] += 1

    items = [{"name": k, "count": v} for k, v in c.most_common(limit)]
    return ok({"items": items})


@insights_api.get("/api/insights/hourly")
@require_dashboard_access()
def hourly():
    """Hourly logs distribution (UTC) for the selected date range."""
    identity = getattr(g, "identity", {}) or {}
    mac_ids = get_allowed_mac_ids(identity)
    start, end, from_s, to_s = get_range_from_request()

    labels = [f"{h:02d}" for h in range(24)]
    buckets = [0 for _ in range(24)]

    for e in iter_log_events(mac_ids, start, end):
        dt = parse_iso(e.get("ts") or "")
        if not dt:
            continue
        h = dt.hour
        if 0 <= h <= 23:
            buckets[h] += 1

    return ok({"labels": labels, "series": [{"name": "Logs", "data": buckets}]})


# --------------------------
# Phase 6: Insights Dashboard (single endpoint)
# --------------------------

@insights_api.get("/api/insights/dashboard")
@require_overview_access()
def dashboard():
    """Phase 6 insights dashboard.

    Returns:
    - KPIs
    - 8 charts payloads (not counting KPI tiles)

    Role scope:
    - C_SUITE: all departments (optionally filter department=...)
    - DEPARTMENT_HEAD: only their department
    - DEPARTMENT_MEMBER: only their department
    """
    identity = getattr(g, "identity", {}) or {}
    mac_ids = get_allowed_mac_ids(identity)
    start, end, from_s, to_s = get_range_from_request()
    labels_days = list(daterange(start, end))
    umap = user_map(mac_ids)

    # If no scope / no users
    if not mac_ids:
        return ok({
            "range": {"from": from_s, "to": to_s},
            "data_in_range": False,
            "scope": {"label": "No users in scope"},
            "kpis": {
                "unique_users": 0,
                "logs": 0,
                "screenshots": 0,
                "total_apps": 0,
                "most_used_app": None,
                "top_category": None,
                "last_updated": None,
                "total_active_minutes": 0,
            },
            "charts": {
                "activity_over_time": {"labels": labels_days, "series": [{"name": "Active Minutes", "data": [0 for _ in labels_days]}]},
                "top_apps": {"items": []},
                "hourly_heatmap": {"week_hour": {}},
                "category_distribution": {"items": []},
                "top_categories": {"items": []},
                "apps_trend": {"labels": labels_days, "keys": [], "rows": [{"day": d} for d in labels_days]},
                "active_by_weekday": {"labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"], "data": [0, 0, 0, 0, 0, 0, 0]},
                "screenshots_over_time": {"labels": labels_days, "series": [{"name": "Screenshots", "data": [0 for _ in labels_days]}]},
            },
        })

    # Pre-fetch all archives in one query per user (production: avoids N*days queries)
    days_set = set(labels_days)
    logs_archives_by_user = {mac: _fetch_archives_by_day(logs, mac, "logs", days_set) for mac in mac_ids}
    shots_archives_by_user = {mac: _fetch_archives_by_day(screenshots, mac, "screenshots", days_set) for mac in mac_ids}

    # Aggregations
    logs_count = 0
    shots_count = 0
    apps_counter = Counter()
    cat_counter = Counter()
    last_updated_dt: Optional[datetime] = None

    # active time inputs
    times_by_user: Dict[str, List[datetime]] = defaultdict(list)

    # per-day activity minutes (computed later)
    per_day_active_seconds = {d: 0 for d in labels_days}

    # per-day screenshots
    shots_by_day = {d: 0 for d in labels_days}

    # per-day app counts (for stacked area)
    app_counts_by_day: Dict[str, Counter] = {d: Counter() for d in labels_days}

    # week-hour heatmap (Mon..Sun x hour)
    week_hour = Counter()

    # Collect log events (using pre-fetched archives for speed)
    for e in iter_log_events(mac_ids, start, end, logs_archives_by_user):
        logs_count += 1
        app = str(e.get("application") or "(unknown)")
        cat = str(e.get("category") or "(unknown)")

        apps_counter[app] += 1
        cat_counter[cat] += 1

        dt = parse_iso(e.get("ts") or "")
        if dt:
            if (last_updated_dt is None) or (dt > last_updated_dt):
                last_updated_dt = dt

            day = dt.strftime("%Y-%m-%d")
            if day in per_day_active_seconds:
                times_by_user[str(e.get("user_mac_id") or "") or "unknown"].append(dt)
                app_counts_by_day[day][app] += 1
                wd = dt.strftime("%a")
                # Normalize to Mon..Sun
                wd = {"Mon": "Mon", "Tue": "Tue", "Wed": "Wed", "Thu": "Thu", "Fri": "Fri", "Sat": "Sat", "Sun": "Sun"}.get(wd, wd)
                week_hour[f"{wd}_{dt.hour}"] += 1

    # Collect screenshot events (using pre-fetched archives for speed)
    for s in iter_screenshot_events(mac_ids, start, end, shots_archives_by_user):
        shots_count += 1
        dt = parse_iso(s.get("ts") or "")
        if dt:
            if (last_updated_dt is None) or (dt > last_updated_dt):
                last_updated_dt = dt
            day = dt.strftime("%Y-%m-%d")
            if day in shots_by_day:
                shots_by_day[day] += 1

    # Active minutes heuristic (total)
    total_active_minutes = compute_active_minutes(times_by_user, gap_minutes=5)

    # Active minutes per day heuristic:
    # We approximate by counting sessions per day using same gap rule
    # (This keeps the chart consistent with KPI total_active_minutes)
    # Build per-day per-user times:
    times_by_user_day: Dict[str, Dict[str, List[datetime]]] = defaultdict(lambda: defaultdict(list))
    for mac, times in times_by_user.items():
        for dt in times:
            d = dt.strftime("%Y-%m-%d")
            if d in per_day_active_seconds:
                times_by_user_day[mac][d].append(dt)
    for mac, days in times_by_user_day.items():
        for d, times in days.items():
            per_day_active_seconds[d] += _sessionize_seconds(times, gap_minutes=5)

    # For large ranges, aggregate chart series to week/month (production: keep payload and charts usable)
    n_days = len(labels_days)
    if n_days > 365:
        bucket_type = "month"
    elif n_days > 90:
        bucket_type = "week"
    else:
        bucket_type = "day"

    if bucket_type == "day":
        chart_labels = labels_days
        activity_minutes_series = [int(per_day_active_seconds[d] // 60) for d in labels_days]
        shots_series = [shots_by_day[d] for d in labels_days]
        # Apps trend: one row per day
        top5_apps = [k for k, _v in apps_counter.most_common(5)]
        apps_trend_rows = [{"day": d, **{app: int(app_counts_by_day[d].get(app, 0)) for app in top5_apps}} for d in labels_days]
    else:
        chart_labels, activity_minutes_series = _aggregate_days_to_buckets(
            labels_days, {d: per_day_active_seconds[d] // 60 for d in labels_days}, bucket_type
        )
        _, shots_series = _aggregate_days_to_buckets(labels_days, dict(shots_by_day), bucket_type)
        top5_apps = [k for k, _v in apps_counter.most_common(5)]
        # Aggregate app counts by bucket
        buckets_app_counts: Dict[str, Counter] = defaultdict(Counter)
        for d in labels_days:
            dt = parse_ymd(d)
            if not dt:
                continue
            if bucket_type == "week":
                y, w, _ = dt.isocalendar()
                key = f"{y}-W{w:02d}"
            else:
                key = d[:7]
            for app in top5_apps:
                buckets_app_counts[key][app] += app_counts_by_day[d].get(app, 0)
        apps_trend_rows = [{"day": k, **{app: int(buckets_app_counts[k].get(app, 0)) for app in top5_apps}} for k in chart_labels]

    # KPIs
    total_apps = len([k for k, v in apps_counter.items() if v > 0 and k != "(unknown)"]) or len(apps_counter)
    most_used_app = apps_counter.most_common(1)[0][0] if apps_counter else None
    top_category = cat_counter.most_common(1)[0][0] if cat_counter else None
    last_updated = last_updated_dt.isoformat() if last_updated_dt else None

    # Charts:
    top_apps_items = [{"name": k, "count": v} for k, v in apps_counter.most_common(10)]
    cat_items = [{"name": k, "count": v} for k, v in cat_counter.most_common(30)]
    top_categories_items = [{"name": k, "count": v} for k, v in cat_counter.most_common(10)]

    # Active time by weekday (bar)
    active_by_wd = Counter()
    for d in labels_days:
        dt = parse_ymd(d)
        if not dt:
            continue
        wd = dt.strftime("%a")
        wd = {"Mon": "Mon", "Tue": "Tue", "Wed": "Wed", "Thu": "Thu", "Fri": "Fri", "Sat": "Sat", "Sun": "Sun"}.get(wd, wd)
        active_by_wd[wd] += int(per_day_active_seconds[d] // 60)

    # Scope label
    role = (identity or {}).get("role_key")
    dept = (identity or {}).get("department")
    if role == ROLE_C_SUITE:
        dep_override = request.args.get("department")
        scope_label = f"All departments" + (f" (filtered: {dep_override})" if dep_override else "")
    elif role == ROLE_DEPT_HEAD:
        scope_label = f"Department: {dept}" if dept else "Department scope"
    else:
        scope_label = "Scoped"

    wh = {k: int(v) for k, v in week_hour.items()}
    data_in_range = logs_count > 0 or shots_count > 0

    return ok(
            {
                "range": {"from": from_s, "to": to_s},
                "data_in_range": data_in_range,
                "bucket": bucket_type,
                "scope": {"label": scope_label, "role_key": role, "department": dept},
                "kpis": {
                    "unique_users": len(set(mac_ids)),
                    "logs": logs_count,
                    "screenshots": shots_count,
                    "total_apps": int(total_apps or 0),
                    "most_used_app": most_used_app,
                    "top_category": top_category,
                    "last_updated": last_updated,
                    "total_active_minutes": int(total_active_minutes or 0),
                },
                "charts": {
                    "activity_over_time": {
                        "labels": chart_labels,
                        "series": [{"name": "Active Minutes", "data": activity_minutes_series}],
                    },
                    "top_apps": {"items": top_apps_items},
                    "hourly_heatmap": {"week_hour": wh},
                    "category_distribution": {"items": cat_items},
                    "top_categories": {"items": top_categories_items},
                    "apps_trend": {
                        "labels": chart_labels,
                        "keys": top5_apps,
                        "rows": apps_trend_rows,
                    },
                    "active_by_weekday": {
                        "labels": ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
                        "data": [active_by_wd[wd] for wd in ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]],
                    },
                    "screenshots_over_time": {
                        "labels": chart_labels,
                        "series": [{"name": "Screenshots", "data": shots_series}],
                    },
                },
            }
        )
