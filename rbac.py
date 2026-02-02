from __future__ import annotations

from functools import wraps
from typing import Any, Dict, Optional

from flask import jsonify, g, request

from auth import jwt_verify, get_user_public

ROLE_C_SUITE = 'C_SUITE'
ROLE_DEPT_HEAD = 'DEPARTMENT_HEAD'
ROLE_DEPT_MEMBER = 'DEPARTMENT_MEMBER'
ROLE_TEAM_MEMBER = ROLE_DEPT_MEMBER

DASHBOARD_ALLOWED_ROLES = {ROLE_C_SUITE, ROLE_DEPT_HEAD}

# Overview-only access: allows aggregated/combined department-level summary.
# IMPORTANT: do NOT use this for user-level endpoints.
OVERVIEW_ALLOWED_ROLES = {ROLE_C_SUITE, ROLE_DEPT_HEAD, ROLE_DEPT_MEMBER}


def _extract_bearer_token() -> Optional[str]:
    auth = request.headers.get('Authorization', '') or ''
    if not auth.startswith('Bearer '):
        return None
    token = auth[7:].strip()
    return token or None


def _build_identity_from_claims(claims: Dict[str, Any]) -> Dict[str, Any]:
    sub = claims.get('sub')
    profile = get_user_public(sub) if sub else None

    role_key = (claims.get('role_key') or claims.get('role') or (profile or {}).get('role_key') or ROLE_DEPT_MEMBER)
    role_key = str(role_key).strip().upper()

    department = claims.get('department') if claims.get('department') is not None else (profile or {}).get('department')
    company_username = claims.get('company_username') if claims.get('company_username') is not None else (profile or {}).get('company_username')
    mac_id = claims.get('mac_id') if claims.get('mac_id') is not None else ((profile or {}).get('user_mac_id') or (profile or {}).get('_id'))

    return {
        'user_id': sub,
        'mac_id': mac_id,
        'company_username': company_username,
        'role_key': role_key,
        'department': department,
        'profile': profile,
    }


def require_dashboard_access():
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = _extract_bearer_token()
            if not token:
                return jsonify({'ok': False, 'error': 'unauthorized'}), 401
            try:
                claims = jwt_verify(token) or {}
            except Exception:
                return jsonify({'ok': False, 'error': 'unauthorized'}), 401

            identity = _build_identity_from_claims(claims)
            if identity.get('role_key') not in DASHBOARD_ALLOWED_ROLES:
                return jsonify({'ok': False, 'error': 'forbidden', 'message': 'Dashboard access denied'}), 403

            g.identity = identity
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def require_overview_access():
    """Allows access to Overview-only endpoints.

    - C_SUITE: org-wide (optionally department=...)
    - DEPARTMENT_HEAD: only their department
    - DEPARTMENT_MEMBER: only their department

    Do NOT use this for user-level endpoints like /api/users, /api/logs, /api/screenshots.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = _extract_bearer_token()
            if not token:
                return jsonify({'ok': False, 'error': 'unauthorized'}), 401
            try:
                claims = jwt_verify(token) or {}
            except Exception:
                return jsonify({'ok': False, 'error': 'unauthorized'}), 401

            identity = _build_identity_from_claims(claims)
            if identity.get('role_key') not in OVERVIEW_ALLOWED_ROLES:
                return jsonify({'ok': False, 'error': 'forbidden', 'message': 'Overview access denied'}), 403

            g.identity = identity
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def require_csuite():
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = _extract_bearer_token()
            if not token:
                return jsonify({'ok': False, 'error': 'unauthorized'}), 401
            try:
                claims = jwt_verify(token) or {}
            except Exception:
                return jsonify({'ok': False, 'error': 'unauthorized'}), 401

            identity = _build_identity_from_claims(claims)
            if identity.get('role_key') != ROLE_C_SUITE:
                return jsonify({'ok': False, 'error': 'forbidden', 'message': 'C_SUITE only'}), 403

            g.identity = identity
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def scope_filter_for_users(identity: dict, department_override: str = None) -> dict:
    role_key = str((identity or {}).get('role_key') or '').strip().upper()
    dept = (identity or {}).get('department')

    if role_key == ROLE_C_SUITE:
        if department_override:
            return {'department': department_override}
        return {}

    if role_key == ROLE_DEPT_HEAD:
        if not dept:
            return {'_id': {'$in': []}}
        return {'department': dept}

    return {'_id': {'$in': []}}
