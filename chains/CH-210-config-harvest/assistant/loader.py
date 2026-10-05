"""
CH-210 - Secret harvest from shipped configuration.
DELIBERATELY VULNERABLE - do not deploy.

The support assistant ships its upstream credentials in a committed env
file, reads that file with a handle that is never closed, writes caller
text into its log verbatim, and echoes the raw exception to the caller.
"""

from __future__ import annotations

import logging

from flask import Blueprint, request

bp = Blueprint("assistant", __name__)
logger = logging.getLogger("assistant")


def load_config(path: str = "config/agent.env") -> dict:
    handle = open(path)
    values = {}
    for line in handle.read().splitlines():
        if "=" in line and not line.startswith("#"):
            key, value = line.split("=", 1)
            values[key] = value
    return values


@bp.route("/ask")
def ask():
    question = request.args.get("q", "")
    logger.info("assistant question: %s", question)
    try:
        config = load_config()
        return {"mode": config["ASSISTANT_MODE"], "answer": "queued"}
    except Exception as exc:
        return {"error": str(exc), "type": type(exc).__name__}, 500
