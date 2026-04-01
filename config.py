import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env from backend directory so CORS/Mongo etc. are correct regardless of cwd
_config_dir = Path(__file__).resolve().parent
load_dotenv(_config_dir / ".env")

# Environment
DEBUG = os.getenv("DEBUG", "1") == "1"

# Server
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "5000"))

# JWT
JWT_SECRET = os.getenv("JWT_SECRET", "mysecretkey")

# Mongo
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB = os.getenv("MONGO_DB", "Discovery_Agent")

# Analysis / Insights date range (production: allow years of data; cap to prevent abuse)
# e.g. 730 = 2 years, 1095 = 3 years. Use 3650 for ~10 years.
MAX_ANALYSIS_DAYS = max(90, min(3650, int(os.getenv("MAX_ANALYSIS_DAYS", "730"))))
# List endpoints (logs/screenshots) can use same or smaller to avoid huge in-memory sort
MAX_LIST_DAYS = max(30, min(MAX_ANALYSIS_DAYS, int(os.getenv("MAX_LIST_DAYS", "365"))))

# CORS (cannot use "*" with supports_credentials=True per CORS spec; use explicit origins)
_DEFAULT_CORS_ORIGINS = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]
CORS_ORIGINS_RAW = (os.getenv("CORS_ORIGINS") or "*").strip()
if CORS_ORIGINS_RAW == "*" or not CORS_ORIGINS_RAW:
    CORS_ORIGINS = _DEFAULT_CORS_ORIGINS.copy()
else:
    CORS_ORIGINS = [o.strip() for o in CORS_ORIGINS_RAW.split(",") if o.strip()]
if not CORS_ORIGINS:
    CORS_ORIGINS = _DEFAULT_CORS_ORIGINS.copy()

# OCR Intermediator (same .env as backend)
MONGO_COLLECTION_SCREENSHOTS = os.getenv("MONGO_COLLECTION", "screenshots")
OCR_STATE_COLLECTION = os.getenv("STATE_COLLECTION", "ocr_state")
OCR_STATE_DOC_ID = os.getenv("STATE_DOC_ID", "global_state")
OCR_AGENT_BATCH_URL = os.getenv("OCR_AGENT_BATCH_URL", "").strip()
OCR_AGENT_HEALTH_URL = (os.getenv("OCR_AGENT_HEALTH_URL", "").strip() or OCR_AGENT_BATCH_URL or "").strip()
OCR_AGENT_TIMEOUT_SEC = float(os.getenv("OCR_AGENT_TIMEOUT_SEC", "240"))
OCR_AGENT_HEALTH_TIMEOUT_SEC = float(os.getenv("OCR_AGENT_HEALTH_TIMEOUT_SEC", "10"))
OCR_BATCH_SIZE = min(5, max(1, int(os.getenv("OCR_BATCH_SIZE", "5"))))
OCR_POLL_INTERVAL_SEC = float(os.getenv("POLL_INTERVAL_SEC", "3"))
OCR_MAX_USERS_PER_CYCLE = int(os.getenv("MAX_USERS_PER_CYCLE", "800"))
OCR_MAX_ITEMS_PER_USER_FETCH = int(os.getenv("MAX_ITEMS_PER_USER_FETCH", "2000"))
OCR_DOWNLOAD_TIMEOUT_SEC = float(os.getenv("DOWNLOAD_TIMEOUT_SEC", "45"))
OCR_MAX_IMAGE_BYTES = int(os.getenv("MAX_IMAGE_BYTES", str(12 * 1024 * 1024)))
OCR_COOLDOWN_SEC = int(os.getenv("COOLDOWN_SEC", "600"))
OCR_COOLDOWN_MAX_ITEMS = int(os.getenv("COOLDOWN_MAX_ITEMS", "5000"))
# Run OCR loop in same process as Flask (set 0 to disable when using multiple workers)
RUN_OCR_WORKER = os.getenv("RUN_OCR_WORKER", "1").strip().lower() in ("1", "true", "yes")
