import re
import uuid

from werkzeug.security import generate_password_hash

from . import storage
from .db import begin, get_db, now_iso

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
CATEGORIES = ["General", "HR", "Contracts", "Engineering", "Audit", "Finance"]


def create_user(username, password, role):
    if not USERNAME_RE.match(username or ""):
        raise ValueError("Username must be 3-32 letters, digits, . _ -")
    if role not in ("admin", "owner", "viewer"):
        raise ValueError("Invalid role")
    if len(password or "") < 10:
        raise ValueError("Password must be at least 10 characters")
    db = get_db()
    begin(db)
    try:
        cur = db.execute(
            "INSERT INTO users(username,password_hash,role,active,created_at) VALUES(?,?,?,1,?)",
            (username, generate_password_hash(password), role, now_iso()),
        )
    except Exception:
        raise ValueError("Username already exists")
    return cur.lastrowid


def create_document(owner_id, name, category, mime, data):
    db = get_db()
    begin(db)
    doc_id = str(uuid.uuid4())
    wrapped = storage.save(doc_id, 1, data)
    t = now_iso()
    db.execute(
        "INSERT INTO documents(id,name,category,owner_id,mime,size,sha256,wrapped_key,"
        "version,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (doc_id, name, category, owner_id, mime, len(data), storage.sha256(data),
         wrapped, 1, t, t),
    )
    return doc_id


def replace_content(doc, data):
    db = get_db()
    begin(db)
    version = doc["version"] + 1
    wrapped = storage.save(doc["id"], version, data)  # old blob key is overwritten: crypto-shredded
    db.execute(
        "UPDATE documents SET version=?, size=?, sha256=?, wrapped_key=?, updated_at=? WHERE id=?",
        (version, len(data), storage.sha256(data), wrapped, now_iso(), doc["id"]),
    )
    return version


def set_grant(doc_id, user_id, level, granted_by, expires_at=None):
    db = get_db()
    begin(db)
    cur = db.execute(
        "SELECT id, level FROM grants WHERE doc_id=? AND user_id=? AND revoked_at IS NULL",
        (doc_id, user_id),
    ).fetchone()
    if cur:
        db.execute("UPDATE grants SET level=?, expires_at=?, granted_by=?, granted_at=? WHERE id=?",
                   (level, expires_at, granted_by, now_iso(), cur["id"]))
        return "updated", cur["level"]
    db.execute(
        "INSERT INTO grants(doc_id,user_id,level,granted_by,granted_at,expires_at) VALUES(?,?,?,?,?,?)",
        (doc_id, user_id, level, granted_by, now_iso(), expires_at),
    )
    return "created", None
