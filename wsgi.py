"""WSGI entrypoint for production servers like Gunicorn."""

from app import app  # Flask app instance
from db import ensure_indexes

# Ensure Mongo indexes exist on startup (safe to ignore failures)
try:
    ensure_indexes()
except Exception:
    pass
