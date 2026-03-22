from typing import Any, Dict, List, Optional, Set

from app.config import COL_USERS
from app.db import get_db


ROLE_C = "C_SUITE"
ROLE_HEAD = "DEPARTMENT_HEAD"
ROLE_MEMBER = "DEPARTMENT_MEMBER"


def role_from_user(doc: Optional[Dict[str, Any]]) -> str:
    if not doc:
        return ""
    return str(doc.get("role_key") or "").upper()


def load_user_by_id(user_mac_id: str) -> Optional[Dict[str, Any]]:
    if not user_mac_id:
        return None
    db = get_db()
    return db[COL_USERS].find_one(
        {"$or": [{"_id": user_mac_id}, {"user_mac_id": user_mac_id}]}
    )


def allowed_user_mac_ids_for_actor(actor: Dict[str, Any]) -> Optional[Set[str]]:
    """
    None = full access (C-Suite).
    Set[str] = only these device ids.
    """
    r = role_from_user(actor)
    if r == ROLE_C:
        return None
    if r == ROLE_HEAD:
        dept = (actor.get("department") or "").strip()
        if not dept:
            return set()
        db = get_db()
        cur = db[COL_USERS].find(
            {"department": dept},
            {"_id": 1, "user_mac_id": 1},
        )
        out: Set[str] = set()
        for d in cur:
            uid = d.get("user_mac_id") or d.get("_id")
            if uid:
                out.add(str(uid))
        return out
    if r == ROLE_MEMBER:
        uid = actor.get("user_mac_id") or actor.get("_id")
        if uid:
            return {str(uid)}
        return set()
    return set()


def can_access_user_mac_id(actor: Dict[str, Any], target_uid: str) -> bool:
    allowed = allowed_user_mac_ids_for_actor(actor)
    if allowed is None:
        return True
    return str(target_uid) in allowed


def list_users_filter_query(actor: Dict[str, Any]) -> Dict[str, Any]:
    r = role_from_user(actor)
    if r == ROLE_C:
        return {}
    if r == ROLE_HEAD:
        dept = (actor.get("department") or "").strip()
        if not dept:
            return {"_id": {"$exists": False}}
        return {"department": dept}
    return {"_id": {"$exists": False}}
