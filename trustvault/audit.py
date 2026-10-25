"""Tamper-evident, append-only audit trail (hash chain + DB triggers)."""
import hashlib
import hmac
import json

from flask import current_app, has_request_context, request

from .db import begin, get_db, now_iso

GENESIS = "0" * 64
FIELDS = ("ts", "actor_id", "actor_name", "role", "action", "doc_id",
          "target_user", "ip", "ua", "result", "detail")


def _canon(e):
    return json.dumps({k: e[k] for k in FIELDS}, sort_keys=True, separators=(",", ":"))


def _hash(prev, e):
    # HMAC with a key that is NOT stored in the database: someone who can edit the DB file
    # cannot recompute a valid chain after altering or deleting entries.
    return hmac.new(current_app.config["_AUDIT_KEY"], (prev + _canon(e)).encode(), hashlib.sha256).hexdigest()


def log(action, result="allowed", user=None, doc_id=None, target=None,
        detail=None, actor_name=None):
    """Write one entry inside the caller's transaction. If this fails, the
    request fails and rolls back: no action without a record."""
    db = get_db()
    begin(db)
    prev = db.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = prev["hash"] if prev else GENESIS
    if has_request_context():
        ip, ua = request.remote_addr, (request.headers.get("User-Agent") or "")[:200]
    else:
        ip, ua = "internal", "internal"
    e = {
        "ts": now_iso(),
        "actor_id": user["id"] if user else None,
        "actor_name": (user["username"] if user else (actor_name or "anonymous"))[:64],
        "role": user["role"] if user else None,
        "action": action,
        "doc_id": str(doc_id)[:64] if doc_id else None,
        "target_user": target,
        "ip": ip,
        "ua": ua,
        "result": result,
        "detail": (detail or "")[:300] or None,
    }
    h = _hash(prev_hash, e)
    db.execute(
        "INSERT INTO audit_log(ts,actor_id,actor_name,role,action,doc_id,target_user,"
        "ip,ua,result,detail,prev_hash,hash) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (*[e[k] for k in FIELDS], prev_hash, h),
    )


def verify():
    """Recompute the whole chain. Detects edits, deletions in the middle,
    and truncation of the tail (via sqlite_sequence)."""
    db = get_db()
    prev, n, expect = GENESIS, 0, 1
    for r in db.execute("SELECT * FROM audit_log ORDER BY id"):
        if r["id"] != expect:
            return {"ok": False, "count": n, "bad_id": expect, "reason": "entry missing"}
        if r["prev_hash"] != prev or _hash(prev, r) != r["hash"]:
            return {"ok": False, "count": n, "bad_id": r["id"], "reason": "entry altered"}
        prev, n, expect = r["hash"], n + 1, expect + 1
    seq = db.execute("SELECT seq FROM sqlite_sequence WHERE name='audit_log'").fetchone()
    if seq and seq["seq"] != n:
        return {"ok": False, "count": n, "bad_id": n + 1, "reason": "entries missing from the end"}
    return {"ok": True, "count": n, "head": prev}
