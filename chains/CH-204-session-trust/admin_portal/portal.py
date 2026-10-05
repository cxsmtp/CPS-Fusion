"""
CH-204 - Session trust to support-desk impersonation.
DELIBERATELY VULNERABLE - do not deploy.

Profile values from the query string are written straight into the session,
and the support desk later shows them to staff as if the server had set
them. A display preference cookie is copied from the request, caller text
is logged verbatim, and responses carry no Content-Security-Policy.
"""

from __future__ import annotations

import logging

from flask import Blueprint, make_response, request, session

bp = Blueprint("support_portal", __name__)
logger = logging.getLogger("support_portal")


@bp.route("/profile")
def save_profile():
    session["display_name"] = request.args.get("display_name", "")
    session["contact_note"] = request.args.get("note", "")
    session["locale"] = request.args.get("locale", "en")
    return {"ok": True}


@bp.route("/audit")
def audit_event():
    event = request.args.get("event", "view")
    logger.info("portal event: %s", event)
    return {"logged": True}


@bp.route("/theme")
def set_theme():
    theme = request.args.get("theme", "light")
    resp = make_response({"ok": True})
    resp.set_cookie("theme", theme, secure=True, httponly=True, samesite="Strict")
    return resp


@bp.route("/ticket")
def ticket_header():
    return {"requester": session.get("display_name", ""), "note": session.get("contact_note", "")}
