import os
from dotenv import load_dotenv

load_dotenv()

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

# CORS
CORS_ORIGINS_RAW = os.getenv("CORS_ORIGINS", "*").strip()
if CORS_ORIGINS_RAW == "*":
    CORS_ORIGINS = "*"
else:
    CORS_ORIGINS = [o.strip() for o in CORS_ORIGINS_RAW.split(",") if o.strip()]

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
