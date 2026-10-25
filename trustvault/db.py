import sqlite3
from datetime import datetime, timedelta, timezone

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL CHECK (role IN ('admin','owner','viewer')),
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  csrf TEXT NOT NULL,
  created_at TEXT NOT NULL,
  last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS login_failures (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL,
  ip TEXT,
  ts TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  category TEXT NOT NULL,
  owner_id INTEGER NOT NULL REFERENCES users(id),
  mime TEXT NOT NULL,
  size INTEGER NOT NULL,
  sha256 TEXT NOT NULL,
  wrapped_key BLOB NOT NULL,
  version INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT
);
CREATE TABLE IF NOT EXISTS grants (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  doc_id TEXT NOT NULL REFERENCES documents(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  level TEXT NOT NULL CHECK (level IN ('read','edit')),
  granted_by INTEGER NOT NULL REFERENCES users(id),
  granted_at TEXT NOT NULL,
  revoked_at TEXT,
  expires_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS one_active_grant
  ON grants(doc_id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_grants_user ON grants(user_id);
CREATE INDEX IF NOT EXISTS idx_docs_owner ON documents(owner_id);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor_id INTEGER,
  actor_name TEXT,
  role TEXT,
  action TEXT NOT NULL,
  doc_id TEXT,
  target_user TEXT,
  ip TEXT,
  ua TEXT,
  result TEXT NOT NULL,
  detail TEXT,
  prev_hash TEXT NOT NULL,
  hash TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_doc ON audit_log(doc_id);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
"""


def now_iso(delta=None):
    t = datetime.now(timezone.utc)
    if delta:
        t = t + delta
    return t.isoformat(timespec="seconds")


def connect(path):
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def get_db():
    if "db" not in g:
        g.db = connect(current_app.config["DB_PATH"])
    return g.db


def begin(db):
    """Take the write lock so check-then-act sequences cannot interleave."""
    if not db.in_transaction:
        db.execute("BEGIN IMMEDIATE")


def init_db(app):
    conn = connect(app.config["DB_PATH"])
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.close()
