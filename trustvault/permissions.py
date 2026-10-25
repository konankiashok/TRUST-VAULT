"""THE authorization gate. Every route that touches a document calls
authorize(); there are no inline permission checks anywhere else.

Rules
- Owner: everything on their own documents.
- Grant 'read': view + download.  Grant 'edit': view + download + edit.
- Only the owner can delete, share (grant/revoke) or see a document's audit.
- Admin: metadata + activity only. An admin can NOT read file contents
  unless explicitly granted like anyone else.
- Default deny. No visibility -> 404 (same as "does not exist");
  visible but not permitted -> 403. Every refusal is audited.
"""
import uuid

from flask import abort

from . import audit
from .db import get_db, now_iso

ALL_ACTIONS = {"view", "download", "edit", "delete", "share", "audit"}
LEVEL_ACTIONS = {
    "owner": set(ALL_ACTIONS),
    "edit": {"view", "download", "edit"},
    "read": {"view", "download"},
}
ADMIN_ACTIONS = {"view", "audit"}  # never "download"


def _parse(doc_id):
    try:
        return str(uuid.UUID(str(doc_id)))
    except (ValueError, AttributeError):
        return None


def _level(db, user, doc):
    if doc["owner_id"] == user["id"]:
        return "owner"
    row = db.execute(
        "SELECT level FROM grants WHERE doc_id=? AND user_id=? "
        "AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at>?)",
        (doc["id"], user["id"], now_iso()),
    ).fetchone()
    return row["level"] if row else None


def _allowed_actions(user, doc, level):
    acts = set(LEVEL_ACTIONS.get(level, ()))
    if user["role"] == "admin":
        acts |= ADMIN_ACTIONS
    return acts


def actions_for(user, doc):
    """For templates only (what buttons to show). Never used to grant access."""
    return _allowed_actions(user, doc, _level(get_db(), user, doc))


def authorize(user, doc_id, action):
    if action not in ALL_ACTIONS:
        raise ValueError(action)
    db = get_db()
    did = _parse(doc_id)
    doc = None
    if did:
        doc = db.execute(
            "SELECT * FROM documents WHERE id=? AND deleted_at IS NULL", (did,)
        ).fetchone()
    allowed = set()
    if doc:
        allowed = _allowed_actions(user, doc, _level(db, user, doc))
    if action in allowed:
        return doc
    visible = bool(allowed)
    audit.log(
        "denied_" + action, "denied", user=user, doc_id=doc_id,
        detail="insufficient permission" if visible else "no such document or no access",
    )
    abort(403 if visible else 404)
