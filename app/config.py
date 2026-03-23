import os
from dotenv import load_dotenv

load_dotenv()


def _get(name: str, default: str = "") -> str:
    return os.environ.get(name, default)


MONGO_URI = _get("MONGO_URI", "mongodb://127.0.0.1:27017")
MONGO_DB_NAME = _get("MONGO_DB_NAME", "DADB")
JWT_SECRET = _get("JWT_SECRET", "dev-secret-change-in-production")
JWT_EXPIRES_HOURS = int(_get("JWT_EXPIRES_HOURS", "72") or "72")

# If true, POST /api/auth/register works without admin token even when users already exist.
# Use for staging / small teams. Production: keep false and add users as logged-in C-Suite.
OPEN_REGISTRATION = _get("OPEN_REGISTRATION", "false").strip().lower() in ("1", "true", "yes", "on")

COL_USERS = "users"
COL_DEPARTMENTS = "departments"
COL_LOGS = "logs"
COL_SCREENSHOTS = "screenshots"
