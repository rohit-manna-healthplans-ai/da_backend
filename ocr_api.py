"""Flask blueprint for OCR status; uses ocr_intermediator.is_ocr_agent_live."""
from flask import Blueprint, jsonify

from ocr_intermediator import is_ocr_agent_live

ocr_api = Blueprint("ocr_api", __name__)


@ocr_api.get("/api/ocr/agent-live")
def agent_live():
    """Return whether the OCR agent is reachable (for monitoring / UI)."""
    return jsonify({"ok": True, "data": {"live": is_ocr_agent_live()}})
