from datetime import datetime, timezone
from functools import lru_cache

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import OperationFailure

from app.config import MONGO_URI, MONGO_DB_NAME, COL_USERS, COL_DEPARTMENTS, COL_LOGS, COL_SCREENSHOTS


def _safe_index(collection, keys, **kwargs):
    """Create index; ignore conflicts if an equivalent index already exists."""
    try:
        collection.create_index(keys, **kwargs)
    except OperationFailure as e:
        code = getattr(e, "code", None)
        if code in (85, 86, 11000):  # IndexOptionsConflict / duplicate name / etc.
            return
        if "already exists" in str(e).lower() or "same name" in str(e).lower():
            return
        raise


@lru_cache(maxsize=1)
def get_client() -> MongoClient:
    # Atlas / remote clusters: slightly higher timeouts reduce flaky "connection closed" on cold start.
    return MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=20000,
        connectTimeoutMS=10000,
        socketTimeoutMS=45000,
        retryWrites=True,
    )


def get_db():
    return get_client()[MONGO_DB_NAME]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_indexes() -> None:
    """Idempotent index creation for fast dashboard queries."""
    db = get_db()

    # users
    _safe_index(db[COL_USERS], [("company_username_norm", ASCENDING)], unique=True, sparse=True)
    _safe_index(db[COL_USERS], [("user_mac_id", ASCENDING)])
    _safe_index(db[COL_USERS], [("department", ASCENDING)])

    # departments
    _safe_index(db[COL_DEPARTMENTS], [("department_code", ASCENDING)], unique=True, sparse=True)
    _safe_index(db[COL_DEPARTMENTS], [("department_name", ASCENDING)])

    # logs — primary read path: user + time (ts)
    _safe_index(db[COL_LOGS], [("user_mac_id", ASCENDING), ("ts", DESCENDING)])
    _safe_index(db[COL_LOGS], [("log_id", ASCENDING)], unique=True, sparse=True)
    _safe_index(db[COL_LOGS], [("screenshot_id", ASCENDING)], sparse=True)
    _safe_index(db[COL_LOGS], [("application", ASCENDING), ("ts", DESCENDING)])
    _safe_index(db[COL_LOGS], [("operation", ASCENDING), ("ts", DESCENDING)])

    # screenshots
    _safe_index(db[COL_SCREENSHOTS], [("user_mac_id", ASCENDING), ("ts", DESCENDING)])
    _safe_index(db[COL_SCREENSHOTS], [("screenshot_id", ASCENDING)], unique=True, sparse=True)
    _safe_index(db[COL_SCREENSHOTS], [("application", ASCENDING), ("ts", DESCENDING)])
    _safe_index(db[COL_SCREENSHOTS], [("operation", ASCENDING), ("ts", DESCENDING)])
