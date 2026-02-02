from pymongo import MongoClient, ASCENDING
from config import MONGO_URI, MONGO_DB

# -----------------------------
# Mongo Connection
# -----------------------------
client = MongoClient(MONGO_URI)
db = client[MONGO_DB]

# -----------------------------
# Collections (exported)
# -----------------------------
users = db["users"]
departments = db["departments"]
logs = db["logs"]
screenshots = db["screenshots"]


def _find_index_by_keys(col, keys):
    """
    keys: list of tuples e.g. [("company_username", 1)]
    returns (index_name, meta) if an index exists with exactly these keys; else (None, None)
    """
    info = col.index_information()
    for name, meta in info.items():
        if meta.get("key") == keys:
            return name, meta
    return None, None


def _ensure_index(col, keys, unique=False, sparse=False):
    """
    Ensures an index exists with the given keys and options.
    - If exists with same keys + same unique/sparse => do nothing
    - If exists with same keys but different options => drop & recreate
    - Otherwise create
    """
    existing_name, meta = _find_index_by_keys(col, keys)
    if existing_name:
        existing_unique = bool(meta.get("unique", False))
        existing_sparse = bool(meta.get("sparse", False))
        if existing_unique == bool(unique) and existing_sparse == bool(sparse):
            return
        try:
            col.drop_index(existing_name)
        except Exception:
            pass

    col.create_index(keys, unique=unique, sparse=sparse)


def ensure_indexes():
    """
    Indexes needed for portal auth + dashboard querying.
    Safe to call multiple times.
    """

    # ---------- Users ----------
    # login searches company_username_norm first, then company_username
    _ensure_index(users, [("company_username_norm", ASCENDING)], unique=True, sparse=True)
    _ensure_index(users, [("company_username", ASCENDING)], unique=True, sparse=True)
    _ensure_index(users, [("department", ASCENDING)], unique=False, sparse=True)
    _ensure_index(users, [("role_key", ASCENDING)], unique=False, sparse=True)
    _ensure_index(users, [("last_seen_at", ASCENDING)], unique=False, sparse=True)

    # ---------- Departments ----------
    _ensure_index(departments, [("name", ASCENDING)], unique=True, sparse=True)

    # ---------- Logs ----------
    # NOTE: Your plugin schema stores logs nested by day under the mac_id doc,
    # but older code may also insert flattened documents. We keep indexes lightweight.
    _ensure_index(logs, [("user_mac_id", ASCENDING)], unique=False, sparse=True)
    _ensure_index(logs, [("department", ASCENDING)], unique=False, sparse=True)
    _ensure_index(logs, [("timestamp", ASCENDING)], unique=False, sparse=True)

    # ---------- Screenshots ----------
    _ensure_index(screenshots, [("user_mac_id", ASCENDING)], unique=False, sparse=True)
    _ensure_index(screenshots, [("department", ASCENDING)], unique=False, sparse=True)
    _ensure_index(screenshots, [("timestamp", ASCENDING)], unique=False, sparse=True)
