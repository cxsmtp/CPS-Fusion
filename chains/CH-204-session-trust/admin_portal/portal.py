"""
CH-204 - Session trust escalation in the admin portal.
DELIBERATELY VULNERABLE - do not deploy.

Preference values from the request are written straight into the session,
and later code trusts the session as if the server had set it. A display
preference cookie is copied from the request, caller text is logged
verbatim, and responses carry no Content-Security-Policy.
"""

from __future__ import annotations

import logging

from flask import Blueprint, make_response, request, session

bp = Blueprint("admin_portal", __name__)
logger = logging.getLogger("admin_portal")


@bp.route("/prefs", methods=["POST"])
def save_preferences():
    session["display_name"] = request.form.get("display_name", "")
    session["preferred_role"] = request.form.get("role", "viewer")
    session["landing_page"] = request.form.get("landing", "/")
    return {"ok": True}


@bp.route("/audit")
def audit_event():
    event = request.args.get("event", "view")
    logger.info("portal event: %s", event)
    return {"logged": True}


@bp.route("/theme", methods=["POST"])
def set_theme():
    theme = request.form.get("theme", "light")
    resp = make_response({"ok": True})
    resp.set_cookie("theme", theme, secure=True, httponly=True, samesite="Strict")
    return resp


@bp.route("/admin")
def admin_home():
    if session.get("preferred_role") == "admin":
        return {"panel": "admin", "user": session.get("display_name")}
    return {"panel": "viewer"}
