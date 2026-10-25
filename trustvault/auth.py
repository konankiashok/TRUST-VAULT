import hashlib
import hmac
import secrets
from datetime import timedelta
from functools import wraps

from flask import abort, current_app, g, redirect, request, session, url_for

from . import audit
from .db import begin, get_db, now_iso

COOKIE = "tv_session"


def _h(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_session(user_id):
    db = get_db()
    begin(db)
    token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(24)
    t = now_iso()
    db.execute("INSERT INTO sessions(token_hash,user_id,csrf,created_at,last_seen) VALUES(?,?,?,?,?)",
               (_h(token), user_id, csrf, t, t))
    return token


def destroy_user_sessions(user_id):
    db = get_db()
    begin(db)
    db.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))


def destroy_current_session():
    token = request.cookies.get(COOKIE)
    if token:
        db = get_db()
        begin(db)
        db.execute("DELETE FROM sessions WHERE token_hash=?", (_h(token),))


def load_user():
    """Every request re-reads the session AND the user row from the database.
    Nothing about identity or role is cached or trusted from the client."""
    g.user, g.csrf = None, None
    token = request.cookies.get(COOKIE)
    if not token or len(token) > 100:
        return
    db = get_db()
    row = db.execute(
        "SELECT u.*, s.csrf AS csrf, s.created_at AS s_created, s.last_seen AS s_seen "
        "FROM sessions s JOIN users u ON u.id=s.user_id "
        "WHERE s.token_hash=? AND u.active=1", (_h(token),)).fetchone()
    if not row:
        return
    cfg = current_app.config
    if (row["s_created"] < now_iso(timedelta(hours=-cfg["SESSION_ABS_HOURS"]))
            or row["s_seen"] < now_iso(timedelta(minutes=-cfg["SESSION_IDLE_MIN"]))):
        begin(db)
        db.execute("DELETE FROM sessions WHERE token_hash=?", (_h(token),))
        return
    if row["s_seen"] < now_iso(timedelta(seconds=-60)):
        begin(db)
        db.execute("UPDATE sessions SET last_seen=? WHERE token_hash=?", (now_iso(), _h(token)))
    g.user, g.csrf = row, row["csrf"]


def check_csrf():
    if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
        return
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    expected = session.get("login_csrf") if request.endpoint == "main.login" else g.csrf
    if not expected or not hmac.compare_digest(sent, expected):
        audit.log("csrf_failed", "denied", user=g.user, detail=request.path[:200])
        abort(400)


def login_required(f):
    @wraps(f)
    def wrapper(*a, **k):
        if not g.user:
            audit.log("denied_unauthenticated", "denied", detail=request.path[:200])
            return redirect(url_for("main.login"))
        return f(*a, **k)
    return wrapper


def roles_required(*roles):
    def deco(f):
        @wraps(f)
        @login_required
        def wrapper(*a, **k):
            if g.user["role"] not in roles:
                audit.log("denied_route", "denied", user=g.user, detail=request.path[:200])
                abort(403)
            return f(*a, **k)
        return wrapper
    return deco
