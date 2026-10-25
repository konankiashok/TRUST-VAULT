"""TrustVault documents: per-document sharing, encrypted storage, tamper-evident audit.

Permission model (matches README / API.md / THREATS.md):
  owner  = the user who uploaded the document. Can do everything to it.
  grant  = the owner gives a named user 'read' (view+download) or 'edit' access,
           optionally expiring. Revoking takes effect on the very next request.
  role owner  -> may upload
  role viewer -> sees only documents shared with them
  role admin  -> sees metadata, activity and permission history of everything,
                 but can NOT download file contents (unless granted like anyone else)
There is ONE decision function, authorize(). Anything you can't see answers 404
(identical to "does not exist"); anything you can see but can't do answers 403.
Every refusal is written to the audit log.
"""
import hashlib
import hmac
import io
import os
import secrets
import sqlite3
import time
import zipfile
from datetime import datetime, timezone

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import (Blueprint, current_app, has_request_context, jsonify, redirect,
                   request, send_file, send_from_directory)

bp = Blueprint("documents", __name__, url_prefix="/api")

MAX_BYTES = 5 * 1024 * 1024
ALLOWED = {
    "pdf": "application/pdf",
    "txt": "text/plain",
    "csv": "text/csv",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}
# level -> what it may do
LEVEL_ACTIONS = {
    "owner": {"view", "download", "edit", "delete", "share", "audit"},
    "edit": {"view", "download", "edit"},
    "read": {"view", "download"},
    "admin": {"view", "audit"},          # metadata + activity only, never contents
}
ZERO = "0" * 64

SCHEMA = """
CREATE TABLE IF NOT EXISTS documents(
  id TEXT PRIMARY KEY,
  owner_id INTEGER NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT '',
  filename TEXT NOT NULL,
  mimetype TEXT NOT NULL,
  size INTEGER NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  blob BLOB NOT NULL,
  nonce BLOB NOT NULL,
  wrapped_key BLOB NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER);
CREATE TABLE IF NOT EXISTS grants(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  doc_id TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  level TEXT NOT NULL CHECK(level IN ('read','edit')),
  granted_by INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER,
  revoked_at INTEGER);
CREATE INDEX IF NOT EXISTS idx_grants_doc ON grants(doc_id, user_id);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  user_id INTEGER,
  user_email TEXT NOT NULL DEFAULT '',
  role TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  doc_id TEXT,
  result TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT '',
  ip TEXT NOT NULL DEFAULT '',
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
  BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
"""


# ------------------------------------------------------------------ setup
def init_documents(app, db_path, user_loader):
    """user_loader(request) -> {"id","email","name","role"} or None."""
    app.config["DOCS_DB_PATH"] = db_path
    app.config["DOCS_USER_LOADER"] = user_loader
    app.config.setdefault("MAX_CONTENT_LENGTH", MAX_BYTES + 1024 * 1024)

    master = os.environ.get("FILE_ENC_KEY")
    if not master:  # local development: keep a key next to the database
        keyfile = os.path.join(os.path.dirname(os.path.abspath(db_path)), ".tv_master_key")
        if not os.path.exists(keyfile):
            with open(keyfile, "w") as f:
                f.write(secrets.token_hex(32))
        master = open(keyfile).read().strip()
    app.config["DOCS_MASTER"] = master.encode()

    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)
    con.commit()
    con.close()
    app.register_blueprint(bp)

    root = os.path.dirname(os.path.abspath(__file__))

    @app.get("/documents")
    def documents_page():
        if not _user():
            return redirect("/")
        resp = send_from_directory(root, "documents.html")
        resp.headers["Cache-Control"] = "no-store"
        return resp

    if os.environ.get("SEED_ON_START", "1") != "0":
        with app.app_context():
            _seed()


def _key(label):
    return hmac.new(current_app.config["DOCS_MASTER"], label, hashlib.sha256).digest()


class Tx:
    """One short transaction: check + act + audit commit or roll back together."""
    def __enter__(self):
        self.c = sqlite3.connect(current_app.config["DOCS_DB_PATH"], timeout=15, isolation_level=None)
        self.c.row_factory = sqlite3.Row
        self.c.execute("BEGIN IMMEDIATE")
        return self.c

    def __exit__(self, t, v, tb):
        try:
            self.c.execute("ROLLBACK" if t else "COMMIT")
        finally:
            self.c.close()
        return False


def _user():
    try:
        u = current_app.config["DOCS_USER_LOADER"](request)
    except Exception:
        return None
    return u if u and u.get("role") in ("owner", "admin", "viewer") else None


def _err(code, msg):
    return jsonify({"error": msg}), code


# ------------------------------------------------------------------ audit
def _audit(c, user, action, doc_id=None, result="ok", detail=""):
    prev = c.execute("SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    prev_hash = prev["hash"] if prev else ZERO
    ts = int(time.time())
    uid = user["id"] if user else None
    email = user["email"] if user else ""
    role = user["role"] if user else ""
    ip = (request.remote_addr or "") if has_request_context() else "system"
    detail = (detail or "")[:300]
    h = _row_hash(prev_hash, ts, uid, email, role, action, doc_id, result, detail, ip)
    c.execute(
        "INSERT INTO audit_log(ts,user_id,user_email,role,action,doc_id,result,detail,ip,prev_hash,hash)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (ts, uid, email, role, action, doc_id, result, detail, ip, prev_hash, h))


def _row_hash(prev_hash, ts, uid, email, role, action, doc_id, result, detail, ip):
    payload = "|".join(str(x if x is not None else "") for x in
                       (prev_hash, ts, uid, email, role, action, doc_id, result, detail, ip))
    return hmac.new(_key(b"audit-chain"), payload.encode(), hashlib.sha256).hexdigest()


def log_event(user, action, result="ok", detail=""):
    """For app.py: record sign-ins, role changes, etc. in the same audit chain."""
    with Tx() as c:
        _audit(c, user, action, None, result, detail)


def verify_chain(c):
    prev, n, last_id = ZERO, 0, 0
    for r in c.execute("SELECT * FROM audit_log ORDER BY id"):
        if r["id"] != last_id + 1:
            return {"ok": False, "message": f"Entries missing before #{r['id']}.", "count": n, "head": prev}
        want = _row_hash(prev, r["ts"], r["user_id"], r["user_email"], r["role"], r["action"],
                         r["doc_id"], r["result"], r["detail"], r["ip"])
        if r["prev_hash"] != prev or not hmac.compare_digest(want, r["hash"]):
            return {"ok": False, "message": f"Entry #{r['id']} was altered.", "count": n, "head": prev}
        prev, last_id, n = r["hash"], r["id"], n + 1
    seq = c.execute("SELECT seq FROM sqlite_sequence WHERE name='audit_log'").fetchone()
    if seq and seq["seq"] != last_id:
        return {"ok": False, "message": "Newest entries were removed.", "count": n, "head": prev}
    return {"ok": True, "message": "Audit chain verified.", "count": n, "head": prev}


# ------------------------------------------------------------------ files
def _clean_name(name):
    name = os.path.basename((name or "").replace("\\", "/"))
    keep = "".join(ch for ch in name if ch.isalnum() or ch in "._- ")
    return keep.strip(" .")[:120] or "file"


def _validate(filename, data):
    """Returns (ext, mimetype, None) or (None, None, error message)."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED:
        return None, None, "File type not allowed. Allowed: " + ", ".join(sorted(ALLOWED)) + "."
    if not data:
        return None, None, "That file is empty."
    if len(data) > MAX_BYTES:
        return None, None, "File is larger than 5 MB."
    ok = True
    if ext == "pdf":
        ok = data.startswith(b"%PDF-")
    elif ext == "png":
        ok = data.startswith(b"\x89PNG\r\n\x1a\n")
    elif ext in ("jpg", "jpeg"):
        ok = data.startswith(b"\xff\xd8\xff")
    elif ext in ("txt", "csv"):
        try:
            data.decode("utf-8")
            ok = b"\x00" not in data
        except UnicodeDecodeError:
            ok = False
    elif ext in ("docx", "xlsx"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                infos = z.infolist()
                ok = ("[Content_Types].xml" in z.namelist() and len(infos) <= 2000
                      and sum(i.file_size for i in infos) <= 100 * 1024 * 1024)
        except zipfile.BadZipFile:
            ok = False
    if not ok:
        return None, None, "The file's contents don't match its type."
    return ext, ALLOWED[ext], None


def _encrypt(doc_id, data):
    fk = AESGCM.generate_key(bit_length=256)
    n1, n2 = os.urandom(12), os.urandom(12)
    blob = AESGCM(fk).encrypt(n1, data, doc_id.encode())
    wrapped = n2 + AESGCM(_key(b"file-wrap")).encrypt(n2, fk, doc_id.encode())
    return blob, n1, wrapped


def _decrypt(doc):
    wrapped = doc["wrapped_key"]
    fk = AESGCM(_key(b"file-wrap")).decrypt(wrapped[:12], wrapped[12:], doc["id"].encode())
    return AESGCM(fk).decrypt(doc["nonce"], doc["blob"], doc["id"].encode())


def _new_doc(c, owner, title, category, filename, mimetype, data):
    doc_id = secrets.token_hex(16)
    blob, nonce, wrapped = _encrypt(doc_id, data)
    now = int(time.time())
    c.execute(
        "INSERT INTO documents(id,owner_id,title,category,filename,mimetype,size,blob,nonce,wrapped_key,created_at,updated_at)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
        (doc_id, owner["id"], title, category, filename, mimetype, len(data), blob, nonce, wrapped, now, now))
    _audit(c, owner, "upload", doc_id, "ok", f"{title} ({filename}, {len(data)} bytes)")
    return doc_id


# ------------------------------------------------------------------ the one rule-holder
_ACTIVE = "g.revoked_at IS NULL AND (g.expires_at IS NULL OR g.expires_at > ?)"


def _level(c, user, doc):
    if doc["owner_id"] == user["id"]:
        return "owner"
    g = c.execute(
        f"SELECT g.level FROM grants g WHERE g.doc_id=? AND g.user_id=? AND {_ACTIVE} "
        "ORDER BY (g.level='edit') DESC LIMIT 1", (doc["id"], user["id"], int(time.time()))).fetchone()
    if g:
        return g["level"]
    return "admin" if user["role"] == "admin" else None


def authorize(c, user, doc_id, action):
    """Returns (doc, level, None) if allowed, else (None, None, (status, message))."""
    doc = c.execute("SELECT * FROM documents WHERE id=? AND deleted_at IS NULL", (str(doc_id),)).fetchone()
    level = _level(c, user, doc) if doc else None
    if not level:
        return None, None, (404, "Document not found.")
    if action not in LEVEL_ACTIONS[level]:
        return None, None, (403, "Your access doesn't allow this.")
    return doc, level, None


def _gate(c, user, doc_id, action):
    """authorize() + audit any refusal. Returns (doc, level, error_response)."""
    doc, level, bad = authorize(c, user, doc_id, action)
    if bad:
        _audit(c, user, action, str(doc_id)[:64], "denied", "not found or hidden" if bad[0] == 404 else "forbidden")
        return None, None, _err(*bad)
    return doc, level, None


def _meta(doc, level, owner_name="", owner_email=""):
    return {
        "id": doc["id"], "title": doc["title"], "category": doc["category"], "filename": doc["filename"],
        "size": doc["size"], "version": doc["version"], "created_at": doc["created_at"],
        "updated_at": doc["updated_at"], "owner": owner_name or owner_email, "owner_email": owner_email,
        "access": level, "can": sorted(LEVEL_ACTIONS[level]),
    }


# ------------------------------------------------------------------ routes
@bp.before_request
def _guard():
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("X-Requested-With") != "TrustVault":
        return _err(403, "Bad request origin.")


@bp.after_request
def _headers(resp):
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


def _like(s):
    return "%" + s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def _day(s, end=False):
    try:
        d = datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None
    return int(d.timestamp()) + (86399 if end else 0)


@bp.get("/documents")
def list_documents():
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    now = int(time.time())
    a = request.args
    # Visibility lives in the SQL itself: own + actively granted (+ every doc's metadata for admins).
    sql = ("SELECT d.*, o.name AS owner_name, o.email AS owner_email FROM documents d "
           "JOIN users o ON o.id=d.owner_id WHERE d.deleted_at IS NULL AND (d.owner_id=? OR EXISTS("
           "SELECT 1 FROM grants g WHERE g.doc_id=d.id AND g.user_id=? AND " + _ACTIVE + ") OR ?=1)")
    args = [u["id"], u["id"], now, 1 if u["role"] == "admin" else 0]
    if a.get("q"):
        sql += " AND (d.title LIKE ? ESCAPE '\\' OR d.filename LIKE ? ESCAPE '\\')"
        args += [_like(a["q"][:100])] * 2
    if a.get("owner"):
        sql += " AND (o.name LIKE ? ESCAPE '\\' OR o.email LIKE ? ESCAPE '\\')"
        args += [_like(a["owner"][:100])] * 2
    if a.get("category"):
        sql += " AND d.category LIKE ? ESCAPE '\\'"
        args.append(_like(a["category"][:60]))
    if _day(a.get("date_from")):
        sql += " AND d.created_at >= ?"
        args.append(_day(a["date_from"]))
    if _day(a.get("date_to")):
        sql += " AND d.created_at <= ?"
        args.append(_day(a["date_to"], True))
    sql += " ORDER BY d.created_at DESC LIMIT 300"
    with Tx() as c:
        out = []
        for d in c.execute(sql, args).fetchall():
            lvl = _level(c, u, d)
            if lvl:
                out.append(_meta(d, lvl, d["owner_name"], d["owner_email"]))
    return jsonify({"documents": out, "can_upload": u["role"] == "owner"})


@bp.post("/documents")
def upload():
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    with Tx() as c:
        if u["role"] != "owner":
            _audit(c, u, "upload", None, "denied", "role cannot upload")
            return _err(403, "Only owners can upload documents.")
        f = request.files.get("file")
        if not f or not f.filename:
            return _err(400, "Choose a file to upload.")
        filename = _clean_name(f.filename)
        data = f.read(MAX_BYTES + 1)
        ext, mime, bad = _validate(filename, data)
        if bad:
            _audit(c, u, "upload", None, "denied", f"rejected {filename}: {bad}")
            return _err(413 if "larger" in bad else 400, bad)
        title = (request.form.get("title") or "").strip()[:150] or filename
        category = (request.form.get("category") or "").strip()[:60]
        doc_id = _new_doc(c, u, title, category, filename, mime, data)
    return jsonify({"id": doc_id}), 201


@bp.get("/documents/<doc_id>")
def view_document(doc_id):
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    with Tx() as c:
        doc, lvl, bad = _gate(c, u, doc_id, "view")
        if bad:
            return bad
        o = c.execute("SELECT name,email FROM users WHERE id=?", (doc["owner_id"],)).fetchone()
        _audit(c, u, "view", doc["id"], "ok", doc["title"])
        return jsonify(_meta(doc, lvl, o["name"], o["email"]))


@bp.get("/documents/<doc_id>/download")
def download(doc_id):
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    with Tx() as c:
        doc, lvl, bad = _gate(c, u, doc_id, "download")
        if bad:
            return bad
        data = _decrypt(doc)
        _audit(c, u, "download", doc["id"], "ok", doc["title"])
    return send_file(io.BytesIO(data), mimetype=doc["mimetype"], as_attachment=True, download_name=doc["filename"])


@bp.put("/documents/<doc_id>")
def edit(doc_id):
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    with Tx() as c:
        doc, lvl, bad = _gate(c, u, doc_id, "edit")
        if bad:
            return bad
        title = (request.form.get("title") or "").strip()[:150]
        category = (request.form.get("category") or "").strip()[:60]
        if not title:
            return _err(400, "Title is required.")
        f = request.files.get("file")
        detail = f"renamed to {title}"
        if f and f.filename:
            data = f.read(MAX_BYTES + 1)
            ext, mime, problem = _validate(_clean_name(f.filename), data)
            if problem:
                _audit(c, u, "edit", doc["id"], "denied", problem)
                return _err(400, problem)
            if mime != doc["mimetype"]:
                _audit(c, u, "edit", doc["id"], "denied", "replacement has a different type")
                return _err(400, "The new file must be the same type as the current one.")
            blob, nonce, wrapped = _encrypt(doc["id"], data)
            c.execute("UPDATE documents SET blob=?,nonce=?,wrapped_key=?,size=?,version=version+1,filename=? WHERE id=?",
                      (blob, nonce, wrapped, len(data), _clean_name(f.filename), doc["id"]))
            detail += f"; new version {doc['version'] + 1}"
        c.execute("UPDATE documents SET title=?,category=?,updated_at=? WHERE id=?",
                  (title, category, int(time.time()), doc["id"]))
        _audit(c, u, "edit", doc["id"], "ok", detail)
    return jsonify({"ok": True})


@bp.delete("/documents/<doc_id>")
def delete(doc_id):
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    with Tx() as c:
        doc, lvl, bad = _gate(c, u, doc_id, "delete")
        if bad:
            return bad
        c.execute("UPDATE documents SET deleted_at=? WHERE id=?", (int(time.time()), doc["id"]))
        _audit(c, u, "delete", doc["id"], "ok", doc["title"])
    return jsonify({"ok": True})


# ----- sharing
def _grant_rows(c, where, args):
    now = int(time.time())
    rows = c.execute(
        "SELECT g.*, t.name AS user_name, t.email AS user_email, b.email AS by_email, d.title AS doc_title "
        "FROM grants g JOIN users t ON t.id=g.user_id JOIN users b ON b.id=g.granted_by "
        "JOIN documents d ON d.id=g.doc_id " + where + " ORDER BY g.id DESC LIMIT 300", args).fetchall()
    out = []
    for g in rows:
        if g["revoked_at"]:
            status = "revoked"
        elif g["expires_at"] and g["expires_at"] <= now:
            status = "expired"
        else:
            status = "active"
        out.append({"id": g["id"], "doc_id": g["doc_id"], "doc_title": g["doc_title"], "user": g["user_name"],
                    "user_email": g["user_email"], "level": g["level"], "granted_by": g["by_email"],
                    "created_at": g["created_at"], "expires_at": g["expires_at"],
                    "revoked_at": g["revoked_at"], "status": status})
    return out


@bp.get("/documents/<doc_id>/grants")
def list_grants(doc_id):
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    with Tx() as c:
        doc, lvl, bad = _gate(c, u, doc_id, "share")
        if bad:
            return bad
        return jsonify({"grants": _grant_rows(c, "WHERE g.doc_id=?", (doc["id"],))})


@bp.post("/documents/<doc_id>/grants")
def add_grant(doc_id):
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    body = request.get_json(silent=True) or {}
    ident = (body.get("username") or "").strip().lower()
    level = body.get("level")
    with Tx() as c:
        doc, lvl, bad = _gate(c, u, doc_id, "share")
        if bad:
            return bad
        if level not in ("read", "edit"):
            return _err(400, "Choose read or edit access.")
        target = c.execute("SELECT id,email,name FROM users WHERE username=? OR email=?", (ident, ident)).fetchone()
        if not target:
            return _err(404, "No user with that username or email.")
        if target["id"] == doc["owner_id"]:
            return _err(400, "That person already owns this document.")
        expires = None
        if body.get("expires_days") not in (None, "", 0):
            try:
                days = int(body["expires_days"])
            except (TypeError, ValueError):
                return _err(400, "Expiry must be a number of days (1-365).")
            if not 1 <= days <= 365:
                return _err(400, "Expiry must be 1-365 days.")
            expires = int(time.time()) + days * 86400
        now = int(time.time())
        c.execute("UPDATE grants SET revoked_at=? WHERE doc_id=? AND user_id=? AND revoked_at IS NULL",
                  (now, doc["id"], target["id"]))
        c.execute("INSERT INTO grants(doc_id,user_id,level,granted_by,created_at,expires_at) VALUES(?,?,?,?,?,?)",
                  (doc["id"], target["id"], level, u["id"], now, expires))
        _audit(c, u, "grant", doc["id"], "ok", f"{level} to {target['email']}")
    return jsonify({"ok": True}), 201


@bp.post("/documents/<doc_id>/grants/<int:grant_id>/revoke")
def revoke_grant(doc_id, grant_id):
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    with Tx() as c:
        doc, lvl, bad = _gate(c, u, doc_id, "share")
        if bad:
            return bad
        g = c.execute("SELECT g.*, t.email FROM grants g JOIN users t ON t.id=g.user_id "
                      "WHERE g.id=? AND g.doc_id=?", (grant_id, doc["id"])).fetchone()
        if not g:
            _audit(c, u, "revoke", doc["id"], "denied", "grant does not belong to this document")
            return _err(404, "Grant not found.")
        c.execute("UPDATE grants SET revoked_at=? WHERE id=? AND revoked_at IS NULL", (int(time.time()), grant_id))
        _audit(c, u, "revoke", doc["id"], "ok", f"revoked {g['email']}")
    return jsonify({"ok": True})


# ----- activity
def _audit_rows(rows):
    return [{"id": r["id"], "ts": r["ts"], "user": r["user_email"], "role": r["role"], "action": r["action"],
             "doc_id": r["doc_id"], "result": r["result"], "detail": r["detail"], "ip": r["ip"]} for r in rows]


@bp.get("/documents/<doc_id>/audit")
def doc_audit(doc_id):
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    with Tx() as c:
        doc, lvl, bad = _gate(c, u, doc_id, "audit")
        if bad:
            return bad
        rows = c.execute("SELECT * FROM audit_log WHERE doc_id=? ORDER BY id DESC LIMIT 200", (doc["id"],)).fetchall()
        return jsonify({"audit": _audit_rows(rows)})


def _admin_only(c, u, what):
    if u["role"] != "admin":
        _audit(c, u, what, None, "denied", "admin area")
        return _err(403, "Admins only.")
    return None


@bp.get("/admin/activity")
def admin_activity():
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    a = request.args
    with Tx() as c:
        bad = _admin_only(c, u, "admin_activity")
        if bad:
            return bad
        sql, args = "SELECT * FROM audit_log WHERE 1=1", []
        if a.get("user"):
            sql += " AND user_email LIKE ? ESCAPE '\\'"
            args.append(_like(a["user"][:100]))
        if a.get("doc"):
            sql += " AND doc_id=?"
            args.append(a["doc"][:64])
        if a.get("action"):
            sql += " AND action=?"
            args.append(a["action"][:30])
        if a.get("result") in ("ok", "denied", "failed"):
            sql += " AND result=?"
            args.append(a["result"])
        if _day(a.get("date_from")):
            sql += " AND ts >= ?"
            args.append(_day(a["date_from"]))
        if _day(a.get("date_to")):
            sql += " AND ts <= ?"
            args.append(_day(a["date_to"], True))
        rows = c.execute(sql + " ORDER BY id DESC LIMIT 300", args).fetchall()
        alerts = c.execute(
            "SELECT a.* FROM audit_log a JOIN grants g ON g.doc_id=a.doc_id AND g.user_id=a.user_id "
            "WHERE a.result='denied' AND g.revoked_at IS NOT NULL AND a.ts >= g.revoked_at "
            "ORDER BY a.id DESC LIMIT 50").fetchall()
        return jsonify({"audit": _audit_rows(rows), "alerts": _audit_rows(alerts), "chain": verify_chain(c)})


@bp.get("/admin/permissions")
def admin_permissions():
    u = _user()
    if not u:
        return _err(401, "Please sign in.")
    with Tx() as c:
        bad = _admin_only(c, u, "admin_permissions")
        if bad:
            return bad
        return jsonify({"grants": _grant_rows(c, "", ())})


# ------------------------------------------------------------------ demo data
def _seed():
    """A small, honest demo: one doc shared with the demo viewer, one shared with nobody."""
    with Tx() as c:
        if c.execute("SELECT 1 FROM documents LIMIT 1").fetchone():
            return
        owner = c.execute("SELECT id,email,name,role FROM users WHERE email='demo-owner@trustvault.demo'").fetchone()
        viewer = c.execute("SELECT id FROM users WHERE email='demo-viewer@trustvault.demo'").fetchone()
        if not owner or not viewer:
            return
        owner = dict(owner)
        shared = _new_doc(c, owner, "Team handbook", "HR", "team-handbook.txt", "text/plain",
                          b"TrustVault demo document.\nThis one is shared (read-only) with the demo viewer.\n")
        _new_doc(c, owner, "Q3 audit notes", "Finance", "q3-audit-notes.txt", "text/plain",
                 b"TrustVault demo document.\nThis one is shared with nobody: a viewer cannot open it.\n")
        c.execute("INSERT INTO grants(doc_id,user_id,level,granted_by,created_at) VALUES(?,?,?,?,?)",
                  (shared, viewer["id"], "read", owner["id"], int(time.time())))
        _audit(c, owner, "grant", shared, "ok", "read to demo-viewer@trustvault.demo")
