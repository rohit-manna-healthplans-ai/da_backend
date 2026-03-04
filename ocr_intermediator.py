"""
OCR Intermediator - runs inside backend repo, uses backend config and db.
Only writes ocr_run + ocr_text on screenshot items; state in ocr_state collection.
Before sending images to OCR, checks that the OCR agent is live (reachable).
"""
from __future__ import annotations

import hashlib
import logging
import time
from collections import deque
from datetime import datetime as dt, timedelta, timezone
from typing import Any, Dict, Deque, List, Optional
from urllib.parse import urlparse

import requests
from pymongo.collection import Collection
from pymongo.errors import ServerSelectionTimeoutError

from config import (
    MONGO_COLLECTION_SCREENSHOTS,
    OCR_AGENT_BATCH_URL,
    OCR_AGENT_HEALTH_URL,
    OCR_AGENT_HEALTH_TIMEOUT_SEC,
    OCR_AGENT_TIMEOUT_SEC,
    OCR_BATCH_SIZE,
    OCR_COOLDOWN_MAX_ITEMS,
    OCR_COOLDOWN_SEC,
    OCR_DOWNLOAD_TIMEOUT_SEC,
    OCR_MAX_IMAGE_BYTES,
    OCR_MAX_ITEMS_PER_USER_FETCH,
    OCR_MAX_USERS_PER_CYCLE,
    OCR_POLL_INTERVAL_SEC,
    OCR_STATE_COLLECTION,
    OCR_STATE_DOC_ID,
)
from db import db, client

# ----------------------------
# Logging
# ----------------------------
LOG_LEVEL = getattr(logging, (__import__("os").getenv("LOG_LEVEL", "INFO").upper()), logging.INFO)


def _logger() -> logging.Logger:
    log = logging.getLogger("ocr_intermediator")
    log.setLevel(LOG_LEVEL)
    if not log.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
        log.addHandler(h)
    return log


logger = _logger()

IST = timezone(timedelta(hours=5, minutes=30))
_session = requests.Session()


# ----------------------------
# Liveness check (before sending to OCR)
# ----------------------------
def is_ocr_agent_live() -> bool:
    """Check if the OCR agent is reachable before sending images. Avoids hanging requests."""
    url = OCR_AGENT_HEALTH_URL or OCR_AGENT_BATCH_URL
    if not url or not url.strip():
        return False
    try:
        # GET with short timeout; many POST-only endpoints return 405, which is fine
        r = _session.get(url.strip(), timeout=OCR_AGENT_HEALTH_TIMEOUT_SEC)
        return r.status_code < 500
    except Exception as e:
        logger.debug("OCR agent liveness check failed: %s", e)
        return False


# ----------------------------
# Time helpers
# ----------------------------
def ist_now() -> dt:
    return dt.now(timezone.utc).astimezone(IST)


def ist_day_key(now: Optional[dt] = None) -> str:
    return (now or ist_now()).strftime("%Y-%m-%d")


def parse_day(s: str) -> dt.date:
    return dt.strptime(s, "%Y-%m-%d").date()


def fmt_day(d: dt.date) -> str:
    return d.strftime("%Y-%m-%d")


def day_add(day: str, days: int) -> str:
    return fmt_day(parse_day(day) + timedelta(days=days))


def utc_iso_now() -> str:
    return dt.now(timezone.utc).isoformat().replace("+00:00", "Z")


# ----------------------------
# Helpers
# ----------------------------
def is_http_url(url: Any) -> bool:
    return isinstance(url, str) and (url.startswith("http://") or url.startswith("https://"))


def guess_ext_from_url(url: str) -> str:
    try:
        path = urlparse(url).path
        if "." in path:
            ext = path.rsplit(".", 1)[-1].lower()
            if ext in ("jpg", "jpeg", "png", "webp", "bmp", "tif", "tiff"):
                return "." + ext
    except Exception:
        pass
    return ".jpg"


def make_item_id(user_id: str, day: str, screenshot_url: str) -> str:
    raw = f"{user_id}|{day}|{screenshot_url}".encode("utf-8", errors="ignore")
    return hashlib.sha1(raw).hexdigest()


def cooldown_until(seconds: int) -> str:
    return (dt.now(timezone.utc) + timedelta(seconds=seconds)).isoformat().replace("+00:00", "Z")


# ----------------------------
# Collections
# ----------------------------
def get_col() -> Collection:
    return db[MONGO_COLLECTION_SCREENSHOTS]


def get_state_col() -> Collection:
    return db[OCR_STATE_COLLECTION]


def load_state(state_col: Collection) -> Dict[str, Any]:
    return state_col.find_one({"_id": OCR_STATE_DOC_ID}) or {}


def save_state(
    state_col: Collection,
    cursor_day: str,
    mode: str,
    cooldown: Dict[str, str],
) -> None:
    if len(cooldown) > OCR_COOLDOWN_MAX_ITEMS:
        items = sorted(cooldown.items(), key=lambda kv: kv[1])
        cooldown = dict(items[-OCR_COOLDOWN_MAX_ITEMS:])
    state_col.update_one(
        {"_id": OCR_STATE_DOC_ID},
        {"$set": {
            "cursor_day": cursor_day,
            "mode": mode,
            "cooldown": cooldown,
            "updated_at": utc_iso_now(),
        }},
        upsert=True,
    )


def find_earliest_day(col: Collection) -> Optional[str]:
    pipeline = [
        {"$project": {"pairs": {"$objectToArray": "$screenshots"}}},
        {"$unwind": "$pairs"},
        {"$group": {"_id": None, "minDay": {"$min": "$pairs.k"}}},
    ]
    res = list(col.aggregate(pipeline, allowDiskUse=True))
    if not res:
        return None
    day = res[0].get("minDay")
    return day if isinstance(day, str) else None


def day_exists_any_user(col: Collection, day: str) -> bool:
    return col.find_one({f"screenshots.{day}": {"$exists": True}}, {"_id": 1}) is not None


def find_next_day_with_data(
    col: Collection,
    start_day: str,
    today_day: str,
    max_scan_days: int = 3650,
) -> Optional[str]:
    d0 = parse_day(start_day)
    dT = parse_day(today_day)
    scanned = 0
    d = d0
    while d <= dT and scanned < max_scan_days:
        key = fmt_day(d)
        if day_exists_any_user(col, key):
            return key
        d += timedelta(days=1)
        scanned += 1
    return None


def fetch_user_docs_for_day(col: Collection, day: str, limit_users: int) -> List[Dict[str, Any]]:
    proj = {"_id": 1, f"screenshots.{day}": 1}
    return list(col.find({f"screenshots.{day}": {"$exists": True}}, proj).limit(limit_users))


def build_pending_queues(
    user_docs: List[Dict[str, Any]],
    day: str,
    cooldown: Dict[str, str],
) -> Dict[str, Deque[Dict[str, Any]]]:
    now_iso = utc_iso_now()
    queues: Dict[str, Deque[Dict[str, Any]]] = {}
    for doc in user_docs:
        user_id = str(doc.get("_id", ""))
        screenshots_obj = doc.get("screenshots")
        arr = (screenshots_obj or {}).get(day) if isinstance(screenshots_obj, dict) else None
        if not isinstance(arr, list):
            continue
        pending: List[Dict[str, Any]] = []
        for item in arr[:OCR_MAX_ITEMS_PER_USER_FETCH]:
            if not isinstance(item, dict):
                continue
            url = item.get("screenshot_url")
            if not is_http_url(url):
                continue
            if item.get("ocr_run") is True:
                continue
            item_id = make_item_id(user_id, day, url)
            cool_until = cooldown.get(item_id)
            if isinstance(cool_until, str) and cool_until and cool_until > now_iso:
                continue
            pending.append({"user_id": user_id, "day": day, "url": url, "item_id": item_id})
        if pending:
            queues[user_id] = deque(pending)
    return queues


def round_robin_batch(
    queues: Dict[str, Deque[Dict[str, Any]]],
    batch_size: int,
) -> List[Dict[str, Any]]:
    users = deque([u for u, q in queues.items() if q])
    batch: List[Dict[str, Any]] = []
    while users and len(batch) < batch_size:
        u = users.popleft()
        q = queues.get(u)
        if not q:
            continue
        batch.append(q.popleft())
        if q:
            users.append(u)
    return batch


def has_any_pending(queues: Dict[str, Deque[Dict[str, Any]]]) -> bool:
    return any(bool(q) for q in queues.values())


def set_item_done(col: Collection, user_id: str, day: str, url: str, text: str) -> None:
    path = f"screenshots.{day}"
    col.update_one(
        {"_id": user_id, path: {"$exists": True}},
        {"$set": {
            f"{path}.$[e].ocr_run": True,
            f"{path}.$[e].ocr_text": text,
        }},
        array_filters=[{"e.screenshot_url": url}],
    )


def download_image_bytes(url: str) -> bytes:
    with _session.get(url, stream=True, timeout=OCR_DOWNLOAD_TIMEOUT_SEC) as r:
        r.raise_for_status()
        buf = bytearray()
        for chunk in r.iter_content(chunk_size=64 * 1024):
            if chunk:
                buf.extend(chunk)
                if len(buf) > OCR_MAX_IMAGE_BYTES:
                    raise ValueError(f"Image too large (>{OCR_MAX_IMAGE_BYTES} bytes)")
        return bytes(buf)


def call_ocr_agent_batch(items: List[Dict[str, Any]]) -> Dict[str, str]:
    files = []
    for it in items:
        ext = guess_ext_from_url(it["url"])
        filename = f"{it['item_id']}{ext}"
        img_bytes = download_image_bytes(it["url"])
        files.append(("files", (filename, img_bytes, "application/octet-stream")))
    resp = _session.post(OCR_AGENT_BATCH_URL, files=files, timeout=OCR_AGENT_TIMEOUT_SEC)
    resp.raise_for_status()
    data = resp.json()
    results = data.get("results")
    if not isinstance(results, list):
        raise ValueError("OCR Agent response missing 'results' list")
    out: Dict[str, str] = {}
    for row in results:
        if not isinstance(row, dict):
            continue
        fname = row.get("filename", "")
        text = row.get("formatted_text", "")
        if isinstance(fname, str) and fname:
            item_id = fname.split(".", 1)[0]
            out[item_id] = text if isinstance(text, str) else str(text)
    return out


def ocr_adaptive(
    col: Collection,
    batch: List[Dict[str, Any]],
    cooldown: Dict[str, str],
) -> int:
    if not batch:
        return 0
    try:
        result_map = call_ocr_agent_batch(batch)
    except Exception as e:
        logger.error("OCR batch failed (%d items): %s", len(batch), e)
        if len(batch) > 1:
            mid = len(batch) // 2
            return ocr_adaptive(col, batch[:mid], cooldown) + ocr_adaptive(col, batch[mid:], cooldown)
        cooldown[batch[0]["item_id"]] = cooldown_until(OCR_COOLDOWN_SEC)
        logger.warning("Single item on cooldown %ds (item_id=%s)", OCR_COOLDOWN_SEC, batch[0]["item_id"])
        return 0
    updated = 0
    for it in batch:
        text = result_map.get(it["item_id"])
        if text is None:
            cooldown[it["item_id"]] = cooldown_until(OCR_COOLDOWN_SEC)
            continue
        set_item_done(col, it["user_id"], it["day"], it["url"], text)
        updated += 1
    return updated


def run_forever() -> None:
    logger.info("OCR Intermediator started (batch=%d)", OCR_BATCH_SIZE)
    logger.info("OCR agent=%s", OCR_AGENT_BATCH_URL or "(not set)")

    try:
        client.admin.command("ping")
    except ServerSelectionTimeoutError as e:
        logger.error("MongoDB connection failed: %s", e)
        raise

    col = get_col()
    state_col = get_state_col()
    today = ist_day_key()
    state = load_state(state_col)
    cursor_day = state.get("cursor_day")
    mode = state.get("mode", "BACKFILL")
    cooldown = state.get("cooldown") if isinstance(state.get("cooldown"), dict) else {}

    if not cursor_day or not isinstance(cursor_day, str):
        earliest = find_earliest_day(col)
        if not earliest:
            logger.warning("No screenshots in DB. Polling...")
            while True:
                time.sleep(OCR_POLL_INTERVAL_SEC)
        cursor_day = earliest
        mode = "BACKFILL"
        save_state(state_col, cursor_day, mode, cooldown)
        logger.info("Initialized state: cursor_day=%s mode=%s", cursor_day, mode)
    else:
        logger.info("Loaded state: cursor_day=%s mode=%s", cursor_day, mode)

    while True:
        try:
            today = ist_day_key()
            next_day = find_next_day_with_data(col, cursor_day, today)
            if not next_day:
                cursor_day = today
                mode = "REALTIME"
                save_state(state_col, cursor_day, mode, cooldown)
                time.sleep(OCR_POLL_INTERVAL_SEC)
                continue

            cursor_day = next_day
            mode = "BACKFILL" if parse_day(cursor_day) < parse_day(today) else "REALTIME"
            user_docs = fetch_user_docs_for_day(col, cursor_day, OCR_MAX_USERS_PER_CYCLE)
            queues = build_pending_queues(user_docs, cursor_day, cooldown)

            if not has_any_pending(queues):
                cursor_day = day_add(cursor_day, 1)
                save_state(state_col, cursor_day, mode, cooldown)
                time.sleep(0.2)
                continue

            # Only send to OCR if agent is live
            if not OCR_AGENT_BATCH_URL or not is_ocr_agent_live():
                logger.warning("OCR agent not live or URL not set; skipping batch (will retry after poll interval)")
                save_state(state_col, cursor_day, mode, cooldown)
                time.sleep(OCR_POLL_INTERVAL_SEC)
                continue

            batch = round_robin_batch(queues, OCR_BATCH_SIZE)
            if not batch:
                save_state(state_col, cursor_day, mode, cooldown)
                time.sleep(OCR_POLL_INTERVAL_SEC)
                continue

            logger.info("Day=%s | OCR batch size=%d", cursor_day, len(batch))
            updated = ocr_adaptive(col, batch, cooldown)
            logger.info("Day=%s | Updated=%d", cursor_day, updated)
            save_state(state_col, cursor_day, mode, cooldown)
            time.sleep(0.2 if updated > 0 else OCR_POLL_INTERVAL_SEC)

        except KeyboardInterrupt:
            logger.info("Shutting down (Ctrl+C).")
            break
        except Exception as e:
            logger.exception("Loop error: %s", e)
            time.sleep(OCR_POLL_INTERVAL_SEC)


if __name__ == "__main__":
    run_forever()
