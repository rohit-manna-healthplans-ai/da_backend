import logging

from flask import Flask, jsonify
from flask_compress import Compress
from flask_cors import CORS

from app.db import ensure_indexes
from app.routes.auth_bp import bp as auth_bp
from app.routes.departments_bp import bp as departments_bp
from app.routes.logs_bp import bp as logs_bp
from app.routes.screenshots_bp import bp as screenshots_bp
from app.routes.users_bp import bp as users_bp

logger = logging.getLogger(__name__)


def create_app():
    app = Flask(__name__)
    CORS(app, supports_credentials=True)
    Compress(app)  # gzip/br — smaller JSON over the wire when deployed

    @app.get("/api/health")
    def health():
        return jsonify({"ok": True, "data": {"status": "up"}})

    app.register_blueprint(auth_bp)
    app.register_blueprint(users_bp)
    app.register_blueprint(departments_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(screenshots_bp)

    with app.app_context():
        try:
            ensure_indexes()
        except Exception as e:
            logger.warning("Could not ensure MongoDB indexes (will retry on next request): %s", e)

    return app
