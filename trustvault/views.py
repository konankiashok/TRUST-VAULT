import io
import re
import secrets
from datetime import datetime, timedelta

from flask import (Blueprint, abort, flash, g, redirect, render_template, request,
                   send_file, session, url_for, current_app)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from . import audit, auth, services, storage, validation
from .auth import COOKIE, login_required, roles_required
from .db import begin, get_db, now_iso
from .permissions import actions_for, authorize

bp = Blueprint("main", __name__)
DUMMY_HASH = generate_password_hash("timing-equalizer-password")


def _date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d") if value else None
    except ValueError:
        return None


@bp.get("/")
def index():
    return redirect(url_for("main.documents" if g.user else "main.login"))


# ------------------------------------------------------------------ auth
def _login_page(error=None, status=200):
    tok = secrets.token_urlsafe(24)
    session["login_csrf"] = tok
    return render_template("login.html", login_csrf=tok, error=error), status


@bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return _login_page()
    username = (request.form.get("username") or "").strip()[:64]
    password = request.form.get("password") or ""
    db = get_db()
    cutoff = now_iso(timedelta(minutes=-15))
    by_user = db.execute("SELECT COUNT(*) c FROM login_failures WHERE username=? AND ts>?",
                         (username.lower(), cutoff)).fetchone()["c"]
    by_ip = db.execute("SELECT COUNT(*) c FROM login_failures WHERE ip=? AND ts>?",
                       (request.remote_addr, cutoff)).fetchone()["c"]
    if by_user >= 5 or by_ip >= 30:
        audit.log("login_blocked", "denied", actor_name=username, detail="too many failures")
        return _login_page("Too many failed attempts. Try again in 15 minutes.", 429)
    user = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    ok = check_password_hash(user["password_hash"] if user else DUMMY_HASH, password)
    if user and ok and user["active"]:
        db.execute("DELETE FROM login_failures WHERE username=?", (username.lower(),))
        token = auth.create_session(user["id"])
        audit.log("login", "allowed", user=user)
        session.pop("login_csrf", None)
        resp = redirect(url_for("main.documents"))
        resp.set_cookie(COOKIE, token, httponly=True, samesite="Strict", path="/",
                        secure=current_app.config["COOKIE_SECURE"],
                        max_age=current_app.config["SESSION_ABS_HOURS"] * 3600)
        return resp
    db.execute("INSERT INTO login_failures(username,ip,ts) VALUES(?,?,?)",
               (username.lower(), request.remote_addr, now_iso()))
    audit.log("login_failed", "denied", actor_name=username, detail="bad credentials or disabled account")
    return _login_page("Invalid username or password.", 401)


@bp.post("/logout")
@login_required
def logout():
    audit.log("logout", "allowed", user=g.user)
    auth.destroy_current_session()
    resp = redirect(url_for("main.login"))
    resp.delete_cookie(COOKIE, path="/")
    return resp


# ------------------------------------------------------------- documents
@bp.get("/documents")
@login_required
def documents():
    a = request.args
    q, owner, cat = (a.get("q") or "").strip()[:100], (a.get("owner") or "").strip()[:64], a.get("category") or ""
    dfrom, dto = _date(a.get("date_from")), _date(a.get("date_to"))
    if (a.get("date_from") and not dfrom) or (a.get("date_to") and not dto):
        flash("Dates must be YYYY-MM-DD.", "error")
    like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
    # Visibility is enforced INSIDE the query: owner, active grant, or admin (metadata only).
    rows = get_db().execute(
        """SELECT d.id, d.name, d.category, d.size, d.version, d.created_at, u.username AS owner_name,
                  CASE WHEN d.owner_id=:uid THEN 'owner'
                       ELSE COALESCE((SELECT g.level FROM grants g WHERE g.doc_id=d.id AND g.user_id=:uid
                                      AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>:now)),
                                     'metadata only') END AS my_level
           FROM documents d JOIN users u ON u.id=d.owner_id
           WHERE d.deleted_at IS NULL
             AND (d.owner_id=:uid OR :adm=1 OR EXISTS (
                    SELECT 1 FROM grants g WHERE g.doc_id=d.id AND g.user_id=:uid
                    AND g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at>:now)))
             AND (:q='' OR d.name LIKE :like ESCAPE '\\')
             AND (:owner='' OR u.username=:owner COLLATE NOCASE)
             AND (:cat='' OR d.category=:cat)
             AND (:dfrom='' OR d.created_at>=:dfrom)
             AND (:dto='' OR d.created_at<:dto)
           ORDER BY d.created_at DESC LIMIT 200""",
        {"uid": g.user["id"], "adm": 1 if g.user["role"] == "admin" else 0, "now": now_iso(),
         "q": q, "like": like, "owner": owner, "cat": cat,
         "dfrom": dfrom.strftime("%Y-%m-%d") if dfrom else "",
         "dto": (dto + timedelta(days=1)).strftime("%Y-%m-%d") if dto else ""},
    ).fetchall()
    return render_template("documents.html", docs=rows, categories=services.CATEGORIES, args=a)


@bp.post("/documents/upload")
@roles_required("owner")
def upload():
    category = request.form.get("category") or "General"
    try:
        if category not in services.CATEGORIES:
            raise ValueError("Unknown category")
        name, mime, data = validation.validate_upload(request.files.get("file"),
                                                      current_app.config["MAX_UPLOAD"])
    except ValueError as e:
        audit.log("upload_rejected", "denied", user=g.user, detail=str(e))
        flash(f"Upload rejected: {e}", "error")
        return redirect(url_for("main.documents"))
    # owner is ALWAYS the logged-in user; any owner_id/role in the form is ignored
    doc_id = services.create_document(g.user["id"], name, category, mime, data)
    audit.log("upload", "allowed", user=g.user, doc_id=doc_id, detail=f"{name} {len(data)}B")
    flash("Uploaded.", "ok")
    return redirect(url_for("main.document", doc_id=doc_id))


@bp.get("/documents/<doc_id>")
@login_required
def document(doc_id):
    doc = authorize(g.user, doc_id, "view")
    acts = actions_for(g.user, doc)
    audit.log("view", "allowed", user=g.user, doc_id=doc["id"])
    db = get_db()
    owner = db.execute("SELECT username FROM users WHERE id=?", (doc["owner_id"],)).fetchone()["username"]
    grants = []
    if "share" in acts:
        grants = db.execute(
            "SELECT g.*, u.username FROM grants g JOIN users u ON u.id=g.user_id "
            "WHERE g.doc_id=? ORDER BY g.id DESC", (doc["id"],)).fetchall()
    return render_template("document.html", doc=doc, acts=acts, owner=owner, grants=grants,
                           categories=services.CATEGORIES, now=now_iso())


@bp.get("/documents/<doc_id>/download")
@login_required
def download(doc_id):
    doc = authorize(g.user, doc_id, "download")
    data = storage.load(doc["id"], doc["version"], doc["wrapped_key"])  # inside the lock
    audit.log("download", "allowed", user=g.user, doc_id=doc["id"], detail=f"v{doc['version']}")
    dl_name = secure_filename(doc["name"]) or "document"
    return send_file(io.BytesIO(data), mimetype=doc["mime"], as_attachment=True, download_name=dl_name)


@bp.post("/documents/<doc_id>/edit")
@login_required
def edit(doc_id):
    doc = authorize(g.user, doc_id, "edit")
    changes = []
    try:
        name = validation.clean_title(request.form.get("name"))
        cat = request.form.get("category") or doc["category"]
        if cat not in services.CATEGORIES:
            raise ValueError("Unknown category")
        f = request.files.get("file")
        if f and f.filename:
            _, mime, data = validation.validate_upload(f, current_app.config["MAX_UPLOAD"])
            if mime != doc["mime"]:
                raise ValueError("Replacement must be the same file type")
            changes.append(f"content v{services.replace_content(doc, data)}")
    except ValueError as e:
        audit.log("edit_rejected", "denied", user=g.user, doc_id=doc["id"], detail=str(e))
        flash(f"Edit rejected: {e}", "error")
        return redirect(url_for("main.document", doc_id=doc["id"]))
    if name != doc["name"]:
        changes.append("renamed")
    if cat != doc["category"]:
        changes.append("category")
    begin(get_db())
    get_db().execute("UPDATE documents SET name=?, category=?, updated_at=? WHERE id=?",
                     (name, cat, now_iso(), doc["id"]))
    audit.log("edit", "allowed", user=g.user, doc_id=doc["id"], detail=", ".join(changes) or "no change")
    flash("Saved.", "ok")
    return redirect(url_for("main.document", doc_id=doc["id"]))


@bp.post("/documents/<doc_id>/delete")
@login_required
def delete(doc_id):
    doc = authorize(g.user, doc_id, "delete")
    get_db().execute("UPDATE documents SET deleted_at=? WHERE id=?", (now_iso(), doc["id"]))
    audit.log("delete", "allowed", user=g.user, doc_id=doc["id"], detail=doc["name"])
    flash("Deleted.", "ok")
    return redirect(url_for("main.documents"))


@bp.post("/documents/<doc_id>/grants")
@login_required
def grant(doc_id):
    doc = authorize(g.user, doc_id, "share")
    username = (request.form.get("username") or "").strip()[:64]
    level = request.form.get("level")
    days = request.form.get("expires_days", "").strip()
    target = get_db().execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    err = None
    if level not in ("read", "edit"):
        err = "Level must be read or edit."
    elif not target or target["id"] == g.user["id"]:
        err = "Choose another active user."
    elif days and not (days.isdigit() and 1 <= int(days) <= 365):
        err = "Expiry must be 1-365 days."
    if err:
        flash(err, "error")
        return redirect(url_for("main.document", doc_id=doc["id"]))
    exp = now_iso(timedelta(days=int(days))) if days else None
    how, old = services.set_grant(doc["id"], target["id"], level, g.user["id"], exp)
    audit.log("grant", "allowed", user=g.user, doc_id=doc["id"], target=target["username"],
              detail=f"{level}" + (f" (was {old})" if old else "") + (f" expires {exp}" if exp else ""))
    flash(f"{how.capitalize()} {level} access for {target['username']}.", "ok")
    return redirect(url_for("main.document", doc_id=doc["id"]))


@bp.post("/documents/<doc_id>/grants/<int:grant_id>/revoke")
@login_required
def revoke(doc_id, grant_id):
    doc = authorize(g.user, doc_id, "share")
    db = get_db()
    row = db.execute(  # grant must belong to THIS document
        "SELECT g.*, u.username FROM grants g JOIN users u ON u.id=g.user_id "
        "WHERE g.id=? AND g.doc_id=? AND g.revoked_at IS NULL", (grant_id, doc["id"])).fetchone()
    if not row:
        abort(404)
    db.execute("UPDATE grants SET revoked_at=? WHERE id=?", (now_iso(), grant_id))
    audit.log("revoke", "allowed", user=g.user, doc_id=doc["id"], target=row["username"])
    flash(f"Access revoked for {row['username']}.", "ok")
    return redirect(url_for("main.document", doc_id=doc["id"]))


@bp.get("/documents/<doc_id>/audit")
@login_required
def doc_audit(doc_id):
    doc = authorize(g.user, doc_id, "audit")
    rows = get_db().execute("SELECT * FROM audit_log WHERE doc_id=? ORDER BY id DESC LIMIT 300",
                            (doc["id"],)).fetchall()
    return render_template("audit.html", doc=doc, rows=rows, title=f"Activity: {doc['name']}")
