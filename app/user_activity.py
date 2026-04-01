"""
Plugin presence for the dashboard must match the same data the UI already shows:
flat documents in `logs` and `screenshots` (see /api/logs, /api/screenshots).

Legacy bucket ingest sets `agent_last_seen_at` on users; many deployments only write
flat rows, so we merge the latest event timestamp from those collections into the API.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from app.config import COL_LOGS, COL_SCREENSHOTS


def _ts_to_aware_dt(val: Any) -> Optional[datetime]:
    if val is None:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    s = str(val).strip()
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None


def _pick_later_ts(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """Return the later of two timestamps; preserves the string form of the chosen value."""
    da = _ts_to_aware_dt(a)
    db = _ts_to_aware_dt(b)
    if da is None and db is None:
        return None
    if da is None:
        return b
    if db is None:
        return a
    return a if da >= db else b


def _normalize_ts_for_json(val: Any) -> str:
    if isinstance(val, datetime):
        return val.isoformat().replace("+00:00", "Z")
    return str(val)


def latest_flat_activity_by_mac(db, mac_ids: List[str]) -> Dict[str, str]:
    """Per user_mac_id: latest `ts` across flat logs + screenshots collections."""
    mac_ids = [str(m).strip() for m in mac_ids if m and str(m).strip()]
    if not mac_ids:
        return {}
    out: Dict[str, str] = {}
    for coll_name in (COL_LOGS, COL_SCREENSHOTS):
        col = db[coll_name]
        try:
            pipe = [
                {"$match": {"user_mac_id": {"$in": mac_ids}}},
                {"$group": {"_id": "$user_mac_id", "max_ts": {"$max": "$ts"}}},
            ]
            for row in col.aggregate(pipe):
                mid = str(row["_id"])
                mt = row.get("max_ts")
                if mt is None:
                    continue
                mt_str = _normalize_ts_for_json(mt)
                if mid not in out:
                    out[mid] = mt_str
                else:
                    picked = _pick_later_ts(out[mid], mt_str)
                    if picked is not None:
                        out[mid] = picked
        except Exception:
            continue
    return out


def enrich_user_agent_presence(db, user_dict: Dict[str, Any]) -> Dict[str, Any]:
    uid = str(user_dict.get("user_mac_id") or user_dict.get("_id") or "").strip()
    if not uid:
        return user_dict
    latest_map = latest_flat_activity_by_mac(db, [uid])
    lt = latest_map.get(uid)
    merged = _pick_later_ts(user_dict.get("agent_last_seen_at"), lt)
    out = dict(user_dict)
    if merged is not None:
        out["agent_last_seen_at"] = merged
    return out


def enrich_users_agent_presence(db, items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if not items:
        return items
    mac_ids = [str(x.get("user_mac_id") or x.get("_id") or "").strip() for x in items]
    mac_ids = [m for m in mac_ids if m]
    latest_map = latest_flat_activity_by_mac(db, mac_ids)
    out: List[Dict[str, Any]] = []
    for u in items:
        uid = str(u.get("user_mac_id") or u.get("_id") or "").strip()
        lt = latest_map.get(uid)
        merged = _pick_later_ts(u.get("agent_last_seen_at"), lt)
        nu = dict(u)
        if merged is not None:
            nu["agent_last_seen_at"] = merged
        out.append(nu)
    return out
