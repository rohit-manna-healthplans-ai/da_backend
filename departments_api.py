"""Departments API (RBAC).

Phase 4 requirements:
 - C_SUITE: can create departments
 - C_SUITE and DEPARTMENT_HEAD: can list departments
"""

from __future__ import annotations

from flask import Blueprint, jsonify, request, g
from pymongo.errors import DuplicateKeyError

from db import departments
from rbac import require_dashboard_access, require_csuite


departments_api = Blueprint("departments_api", __name__)


def ok(data=None, status: int = 200):
    return jsonify({"ok": True, "data": data}), status


def err(msg: str, status: int = 400):
    return jsonify({"ok": False, "error": msg}), status


@departments_api.get("/api/departments")
@require_dashboard_access()
def list_departments_route():
    items = [d.get("name") for d in departments.find({}, {"_id": 0, "name": 1}).sort("name", 1)]
    return ok(items)


@departments_api.post("/api/departments")
@require_csuite()
def create_department_route():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return err("name required", 400)
    try:
        departments.insert_one({"name": name})
    except DuplicateKeyError:
        return err("department already exists", 409)
    return ok(name, 201)
