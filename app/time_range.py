"""
Dashboard sends `from` / `to` as YYYY-MM-DD (browser local).
We interpret as UTC day boundaries for consistent Mongo string compare on ISO `ts`.
(If you need local TZ, switch to zoneinfo and convert.)
"""
from datetime import datetime, timedelta, timezone


def _parse_ymd(s: str) -> datetime:
    """Parse YYYY-MM-DD as UTC midnight."""
    parts = s.strip().split("-")
    if len(parts) != 3:
        raise ValueError("Invalid date")
    y, m, d = int(parts[0]), int(parts[1]), int(parts[2])
    return datetime(y, m, d, tzinfo=timezone.utc)


def range_iso_strings(from_str: str, to_str: str) -> tuple[str, str]:
    """
    Inclusive range on calendar days [from, to] in UTC.
    Returns (start_iso, end_iso) suitable for comparing string `ts` field
    when stored as ISO-8601 (lexicographic order matches time order).
    """
    start = _parse_ymd(from_str)
    end_day = _parse_ymd(to_str)
    end = end_day + timedelta(days=1) - timedelta(microseconds=1)
    return start.isoformat().replace("+00:00", "Z"), end.isoformat().replace("+00:00", "Z")


def mongo_time_or_query(start_iso: str, end_iso: str) -> dict:
    """
    Prefer event time `ts`; if missing, fall back to `created_at` (batch insert time).
    """
    return {
        "$or": [
            {"ts": {"$gte": start_iso, "$lte": end_iso}},
            {
                "$and": [
                    {"$or": [{"ts": {"$exists": False}}, {"ts": None}, {"ts": ""}]},
                    {"created_at": {"$gte": start_iso, "$lte": end_iso}},
                ]
            },
        ]
    }
