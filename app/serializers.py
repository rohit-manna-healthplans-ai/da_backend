"""Strip secrets and normalize API shapes."""
from typing import Any, Dict


def user_public(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return {}
    out = dict(doc)
    out.pop("password_hash", None)
    # Ensure stable id for dashboard
    uid = out.get("user_mac_id") or out.get("_id")
    if uid is not None:
        out["_id"] = uid
        out["user_mac_id"] = uid
    return out


def department_public(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return {}
    return {
        "_id": doc.get("_id"),
        "department_name": doc.get("department_name"),
        "department_code": doc.get("department_code") or doc.get("_id"),
        "is_active": doc.get("is_active", True),
        "created_at": doc.get("created_at"),
        "updated_at": doc.get("updated_at"),
    }


def log_row(doc: Dict[str, Any]) -> Dict[str, Any]:
    """Flatten log document for dashboard."""
    if not doc:
        return {}
    out = {
        "_id": str(doc.get("_id")) if doc.get("_id") is not None else None,
        "log_id": doc.get("log_id"),
        "user_mac_id": doc.get("user_mac_id"),
        "pc_username": doc.get("pc_username"),
        "ts": doc.get("ts"),
        "category": doc.get("category"),
        "details": doc.get("details"),
        "application": doc.get("application"),
        "window_title": doc.get("window_title"),
        "operation": doc.get("operation"),
        "screenshot_id": doc.get("screenshot_id"),
        "created_at": doc.get("created_at"),
    }
    return out


def screenshot_row(doc: Dict[str, Any]) -> Dict[str, Any]:
    if not doc:
        return {}
    op = doc.get("operation")
    out = {
        "_id": str(doc.get("_id")) if doc.get("_id") is not None else None,
        "screenshot_id": doc.get("screenshot_id"),
        "user_mac_id": doc.get("user_mac_id"),
        "pc_username": doc.get("pc_username"),
        "ts": doc.get("ts"),
        "application": doc.get("application"),
        "window_title": doc.get("window_title"),
        "operation": op,
        "label": doc.get("label") or op,
        "file_path": doc.get("file_path"),
        "screenshot_url": doc.get("screenshot_url"),
        "created_at": doc.get("created_at"),
    }
    return out
