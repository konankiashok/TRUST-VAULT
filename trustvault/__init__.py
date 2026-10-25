import os
import secrets

from flask import Flask, g, render_template, request
from werkzeug.middleware.proxy_fix import ProxyFix

from . import admin, auth, storage, views
from .db import begin, get_db, init_db


def _secret(app, env_name, prod):
    """Env var wins. In production it is mandatory; in dev we generate and persist one."""
    val = os.environ.get(env_name)
    if val:
        return val
    if prod:
        raise RuntimeError(f"{env_name} must be set in production")
    path = os.path.join(app.config["DATA_DIR"], f".{env_name.lower()}")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_urlsafe(48))
    with open(path) as f:
        return f.read().strip()


def create_app(overrides=None):
    app = Flask(__name__)
    prod = os.environ.get("TV_ENV", "dev") == "production"
    data_dir = (overrides or {}).get("DATA_DIR") or os.environ.get("DATA_DIR") or os.path.join(os.getcwd(), "data")
    app.config.update(
        DATA_DIR=data_dir,
        MAX_CONTENT_LENGTH=6 * 1024 * 1024, MAX_UPLOAD=5 * 1024 * 1024,
        COOKIE_SECURE=prod, SESSION_ABS_HOURS=8, SESSION_IDLE_MIN=60,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict", SESSION_COOKIE_SECURE=prod,
        SEED_ON_START=os.environ.get("SEED_ON_START") == "1",
    )
    app.config.update(overrides or {})
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    app.config["BLOB_DIR"] = os.path.join(data_dir, "blobs")
    os.makedirs(app.config["BLOB_DIR"], mode=0o700, exist_ok=True)
    app.config["DB_PATH"] = os.path.join(data_dir, "trustvault.db")
    app.secret_key = app.config.get("SECRET_KEY") or _secret(app, "SECRET_KEY", prod)
    enc = app.config.get("FILE_ENC_KEY") or _secret(app, "FILE_ENC_KEY", prod)
    app.config["_MASTER"] = storage.derive_master(enc)
    app.config["_AUDIT_KEY"] = storage.derive(enc, b"trustvault-audit-hmac")
    if os.environ.get("TRUST_PROXY") == "1":
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

    init_db(app)
    app.register_blueprint(views.bp)
    app.register_blueprint(admin.bp)

    @app.before_request
    def _before():
        if request.endpoint == "static":
            g.user = g.csrf = None
            return
        db = get_db()
        # take the write lock up front for anything that mutates or touches a document,
        # so "check permission" and "act + audit" are one atomic step
        if request.method != "GET" or (request.view_args or {}).get("doc_id"):
            begin(db)
        auth.load_user()
        auth.check_csrf()

    @app.after_request
    def _after(resp):
        db = g.get("db")
        if db is not None and db.in_transaction:
            db.commit() if resp.status_code < 500 else db.rollback()
        if request.endpoint != "static":
            resp.headers["Cache-Control"] = "no-store"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Content-Security-Policy"] = (
            "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; "
            "frame-ancestors 'none'; base-uri 'none'")
        if prod:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return resp

    @app.teardown_appcontext
    def _close(exc):
        db = g.pop("db", None)
        if db is not None:
            if db.in_transaction:
                db.rollback()
            db.close()

    def _err(code, msg):
        def handler(e):
            return render_template("error.html", code=code, msg=msg), code
        return handler

    for code, msg in [(400, "Bad request"), (403, "You don't have permission to do that"),
                      (404, "Not found"), (405, "Method not allowed"),
                      (413, "File too large"), (429, "Too many requests"),
                      (500, "Something went wrong")]:
        app.register_error_handler(code, _err(code, msg))

    if app.config["SEED_ON_START"]:
        with app.app_context():
            if get_db().execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
                from . import seed
                seed.run(app)
    return app
