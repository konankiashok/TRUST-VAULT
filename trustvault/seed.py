from . import audit, services
from .db import get_db

USERS = [
    ("admin", "Admin-Demo-2026!", "admin"),
    ("alice", "Alice-Demo-2026!", "owner"),
    ("bob", "Bob-Demo-2026!", "owner"),
    ("carol", "Carol-Demo-2026!", "viewer"),
    ("dave", "Dave-Demo-2026!", "viewer"),
]

DOCS = [
    ("alice", "salary-letter-carol.txt", "HR", b"Salary letter for Carol. Confidential.\n", [("carol", "read")]),
    ("alice", "q3-audit-notes.txt", "Audit", b"Q3 audit working notes. Alice only.\n", []),
    ("bob", "customer-contract.txt", "Contracts", b"Customer contract draft. Bob and Dave.\n", [("dave", "read")]),
    ("bob", "drawing-spec.txt", "Engineering", b"Partner drawing specification v1.\n", [("dave", "edit")]),
]


def run(app):
    with app.app_context():
        db = get_db()
        db.execute("BEGIN IMMEDIATE")
        ids = {}
        for name, pw, role in USERS:
            ids[name] = services.create_user(name, pw, role)
        row = lambda n: db.execute("SELECT * FROM users WHERE id=?", (ids[n],)).fetchone()
        for owner, fname, cat, data, grants in DOCS:
            doc_id = services.create_document(ids[owner], fname, cat, "text/plain", data)
            audit.log("upload", user=row(owner), doc_id=doc_id, detail=f"{fname} (seed)")
            for who, level in grants:
                services.set_grant(doc_id, ids[who], level, ids[owner])
                audit.log("grant", user=row(owner), doc_id=doc_id, target=who, detail=f"{level} (seed)")
        db.commit()
