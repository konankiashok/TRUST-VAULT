import hashlib, hmac, json, os, re, secrets, sqlite3, time, urllib.request
from functools import wraps
from flask import Flask, g, jsonify, redirect, request, send_file, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE, "trustvault.db"))
ROLES = ("owner", "admin", "viewer")
# Keep this OFF in production: it lets anyone pick Owner/Admin at sign-up.
ALLOW_ROLE_SELECT = os.environ.get("ALLOW_ROLE_SELECT") == "1"

# Email login codes
CODE_TTL = 600        # a code works for 10 minutes
MAX_ATTEMPTS = 5      # wrong guesses allowed per code
RESEND_WAIT = 60      # seconds between codes for the same email
BREVO_API_KEY = os.environ.get("BREVO_API_KEY")
MAIL_FROM = os.environ.get("MAIL_FROM")  # must be a sender you verified in Brevo
MAIL_FROM_NAME = os.environ.get("MAIL_FROM_NAME", "TrustVault")
LOG_CODES = os.environ.get("LOG_CODES") == "1"  # testing only: prints codes in the server log

app = Flask(__name__)
if os.environ.get("TRUST_PROXY") == "1":   # Render sits behind one proxy: keep real client IPs for the audit log
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=bool(os.environ.get("RENDER")),  # HTTPS on Render
)

# ---------- database ----------
def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'viewer',
        is_demo INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS login_codes(
        email TEXT PRIMARY KEY,
        code_hash TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        attempts INTEGER NOT NULL DEFAULT 0,
        sent_at INTEGER NOT NULL)""")
    # Demo accounts: nobody knows their password, they're only reachable via the demo buttons.
    for role in ROLES:
        email = f"demo-{role}@trustvault.demo"
        conn.execute(
            "INSERT OR IGNORE INTO users(name,email,username,password_hash,role,is_demo) VALUES(?,?,?,?,?,1)",
            (f"Demo {role.title()}", email, f"demo-{role}",
             generate_password_hash(secrets.token_urlsafe(32)), role))
    conn.commit()
    conn.close()

init_db()

# ---------- documents (sharing, encryption, audit) ----------
from documents import init_documents, log_event

def user_for_docs(req):
    uid = session.get("uid")
    if not uid:
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    row = conn.execute("SELECT id, email, name, role FROM users WHERE id=?", (uid,)).fetchone()
    conn.close()
    return dict(row) if row else None   # role is re-read from the database on every request

init_documents(app, DB_PATH, user_for_docs)

# ---------- helpers ----------
def err(message, code=400):
    return jsonify(message=message), code

def current_user():
    uid = session.get("uid")
    if not uid:
        return None
    return db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

def public(u):
    return {"id": u["id"], "name": u["name"], "email": u["email"],
            "role": u["role"], "is_demo": bool(u["is_demo"])}

def login_required(*roles):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                return err("Please sign in.", 401)
            if roles and u["role"] not in roles:
                return err("Your role doesn't allow this.", 403)
            return fn(u, *a, **kw)
        return wrapper
    return deco

def start_session(user):
    session.clear()
    session["uid"] = user["id"]

# ---------- auth ----------
@app.post("/api/auth/register")
def register():
    d = request.get_json(silent=True) or {}
    name = (d.get("name") or "").strip()
    email = (d.get("email") or "").strip().lower()
    password = d.get("password") or ""
    if not name:
        return err("Enter your full name.")
    if not re.match(r"^\S+@\S+\.\S+$", email):
        return err("Enter a valid email address.")
    if len(password) < 8:
        return err("Password must be at least 8 characters.")

    conn = db()
    if conn.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
        return err("An account with this email already exists.", 409)

    real_users = conn.execute("SELECT COUNT(*) c FROM users WHERE is_demo=0").fetchone()["c"]
    if real_users == 0:
        role = "owner"                       # first real account owns the vault
    elif ALLOW_ROLE_SELECT and d.get("role") in ROLES:
        role = d["role"]
    else:
        role = "viewer"                      # everyone else starts read-only

    base = re.sub(r"[^a-z0-9._-]", "", email.split("@")[0]) or "user"
    username, n = base, 1
    while conn.execute("SELECT 1 FROM users WHERE username=?", (username,)).fetchone():
        n += 1
        username = f"{base}{n}"

    cur = conn.execute(
        "INSERT INTO users(name,email,username,password_hash,role) VALUES(?,?,?,?,?)",
        (name, email, username, generate_password_hash(password), role))
    conn.commit()
    user = conn.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
    start_session(user)
    return jsonify(user=public(user)), 201

@app.post("/api/auth/login")
def login():
    d = request.get_json(silent=True) or {}
    ident = (d.get("identifier") or "").strip().lower()
    password = d.get("password") or ""
    if not ident or not password:
        return err("Enter your email or username and your password.")
    user = db().execute(
        "SELECT * FROM users WHERE (email=? OR username=?) AND is_demo=0", (ident, ident)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        log_event(None, "login", "failed", f"identifier: {ident[:80]}")
        return err("Email, username or password is incorrect.", 401)
    start_session(user)
    log_event(dict(user), "login", "ok")
    return jsonify(user=public(user))

@app.post("/api/auth/demo")
def demo():
    role = (request.get_json(silent=True) or {}).get("role")
    if role not in ROLES:
        return err("Choose Owner, Admin or Viewer.")
    user = db().execute("SELECT * FROM users WHERE email=?", (f"demo-{role}@trustvault.demo",)).fetchone()
    start_session(user)
    return jsonify(user=public(user))

@app.post("/api/auth/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

# ---------- email code login ----------
def hash_code(email, code):
    return hmac.new(app.secret_key.encode(), f"{email}:{code}".encode(), hashlib.sha256).hexdigest()

def send_code_email(to, code):
    if not (BREVO_API_KEY and MAIL_FROM):
        if LOG_CODES:
            app.logger.warning("TEST MODE: login code for %s is %s", to, code)
        else:
            app.logger.error("Email is not set up (BREVO_API_KEY / MAIL_FROM missing).")
        return
    payload = {
        "sender": {"name": MAIL_FROM_NAME, "email": MAIL_FROM},
        "to": [{"email": to}],
        "subject": f"Your TrustVault login code: {code}",
        "htmlContent": (f"<p>Your TrustVault login code is:</p>"
                        f"<p style='font-size:28px;letter-spacing:6px'><b>{code}</b></p>"
                        f"<p>It expires in {CODE_TTL // 60} minutes. If you didn't ask for it, ignore this email.</p>"),
    }
    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email", data=json.dumps(payload).encode(), method="POST",
        headers={"api-key": BREVO_API_KEY, "Content-Type": "application/json", "accept": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=10).read()
    except Exception as e:
        app.logger.error("Could not send login code: %s", e)

@app.post("/api/auth/code/request")
def code_request():
    email = ((request.get_json(silent=True) or {}).get("email") or "").strip().lower()
    if not re.match(r"^\S+@\S+\.\S+$", email):
        return err("Enter a valid email address.")
    conn = db()
    user = conn.execute("SELECT 1 FROM users WHERE email=? AND is_demo=0", (email,)).fetchone()
    now = int(time.time())
    row = conn.execute("SELECT sent_at FROM login_codes WHERE email=?", (email,)).fetchone()
    # Same answer whether or not the account exists, so nobody can probe for emails.
    if user and not (row and now - row["sent_at"] < RESEND_WAIT):
        code = f"{secrets.randbelow(10**6):06d}"
        conn.execute("INSERT OR REPLACE INTO login_codes(email,code_hash,expires_at,attempts,sent_at) VALUES(?,?,?,?,?)",
                     (email, hash_code(email, code), now + CODE_TTL, 0, now))
        conn.commit()
        send_code_email(email, code)
    return jsonify(ok=True)

@app.post("/api/auth/code/verify")
def code_verify():
    d = request.get_json(silent=True) or {}
    email = (d.get("email") or "").strip().lower()
    code = str(d.get("code") or "").strip()
    if not re.fullmatch(r"\d{6}", code):
        return err("Enter the 6-digit code from your email.")
    bad = "That code is wrong or has expired. Ask for a new one."
    conn = db()
    row = conn.execute("SELECT * FROM login_codes WHERE email=?", (email,)).fetchone()
    if not row or row["expires_at"] < time.time() or row["attempts"] >= MAX_ATTEMPTS:
        return err(bad, 401)
    if not hmac.compare_digest(row["code_hash"], hash_code(email, code)):
        conn.execute("UPDATE login_codes SET attempts=attempts+1 WHERE email=?", (email,))
        conn.commit()
        return err(bad, 401)
    conn.execute("DELETE FROM login_codes WHERE email=?", (email,))
    conn.commit()
    user = conn.execute("SELECT * FROM users WHERE email=? AND is_demo=0", (email,)).fetchone()
    if not user:
        return err(bad, 401)
    start_session(user)
    return jsonify(user=public(user))

# ---------- API ----------
@app.get("/api/me")
@login_required()
def me(u):
    return jsonify(user=public(u))

@app.get("/api/users")
@login_required("owner", "admin")
def users(u):
    rows = db().execute("SELECT * FROM users WHERE is_demo=0 ORDER BY id").fetchall()
    return jsonify(users=[public(r) for r in rows])

@app.post("/api/users/<int:uid>/role")
@login_required("owner")
def set_role(u, uid):
    role = (request.get_json(silent=True) or {}).get("role")
    if role not in ROLES:
        return err("Unknown role.")
    if uid == u["id"]:
        return err("You can't change your own role.", 403)
    target = db().execute("SELECT * FROM users WHERE id=? AND is_demo=0", (uid,)).fetchone()
    if not target:
        return err("User not found.", 404)
    db().execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    db().commit()
    log_event(dict(u), "role_change", "ok", f"{target['email']}: {target['role']} -> {role}")
    return jsonify(ok=True)

# ---------- pages ----------
@app.get("/")
def index():
    if current_user():
        return redirect("/dashboard")
    return send_file(os.path.join(BASE, "login.html"))

@app.get("/login")
def login_page():
    return index()

DASHBOARD = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>TrustVault</title>
<style>
body{margin:0;font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#EEF2F5;color:#12263A}
header{background:#12263A;color:#fff;padding:14px 24px;display:flex;justify-content:space-between;align-items:center}
main{max-width:760px;margin:28px auto;padding:0 16px}
.card{background:#fff;border:1px solid #CBD5DE;border-radius:12px;padding:20px;margin-bottom:18px}
.badge{display:inline-block;padding:2px 10px;border-radius:99px;font-size:.8rem;font-weight:600;color:#fff}
.owner{background:#8A5A00}.admin{background:#1D4E89}.viewer{background:#47606F}
button,select{font:inherit;padding:7px 12px;border-radius:8px;border:1px solid #8FA1B2;background:#fff;cursor:pointer}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:8px 6px;border-bottom:1px solid #E1E8EE}
.note{background:#FFF6DD;border:1px solid #E9D28A;padding:10px 12px;border-radius:8px;font-size:.9rem}
</style></head><body>
<header><strong>TrustVault</strong><span><span id="who"></span> <button id="out">Sign out</button></span></header>
<main>
<div id="demo" class="note" hidden>You're in a demo account. Changes here aren't saved to a real account.</div>
<div class="card"><h2 id="hello"></h2><p id="perm"></p><p><a href="/documents"><b>Open documents &rarr;</b></a></p></div>
<div class="card" id="usersCard" hidden><h3>Members</h3><table id="tbl"></table></div>
</main>
<script>
const PERMS={owner:"You can upload documents, share them with named people, and revoke access at any time.",
admin:"You manage members and can see all activity and permissions. You can't open file contents unless an owner shares them with you.",viewer:"You can open the documents that owners have shared with you."};
const $=s=>document.querySelector(s);
async function api(u,o){const r=await fetch(u,{credentials:"include",headers:{"Content-Type":"application/json"},...o});
if(r.status===401){location.href="/";throw 0}return r.json()}
(async()=>{
 const {user}=await api("/api/me");
 $("#hello").textContent="Welcome, "+user.name;
 $("#perm").textContent=PERMS[user.role];
 const b=document.createElement("span");b.className="badge "+user.role;b.textContent=user.role;
 $("#who").append(user.email+" ",b);
 $("#demo").hidden=!user.is_demo;
 if(user.role==="viewer")return;
 const {users}=await api("/api/users");
 $("#usersCard").hidden=false;
 const t=$("#tbl");
 t.innerHTML="<tr><th>Name</th><th>Email</th><th>Role</th></tr>";
 users.forEach(m=>{
  const tr=t.insertRow();
  tr.insertCell().textContent=m.name;
  tr.insertCell().textContent=m.email;
  const c=tr.insertCell();
  if(user.role==="owner"&&m.id!==user.id&&!user.is_demo){
   const s=document.createElement("select");
   ["owner","admin","viewer"].forEach(r=>{const o=new Option(r,r,false,r===m.role);s.add(o)});
   s.onchange=async()=>{await api("/api/users/"+m.id+"/role",{method:"POST",body:JSON.stringify({role:s.value})})};
   c.append(s);
  }else c.textContent=m.role;
 });
})();
$("#out").onclick=async()=>{await api("/api/auth/logout",{method:"POST"});location.href="/"};
</script></body></html>"""

@app.get("/dashboard")
def dashboard():
    if not current_user():
        return redirect("/")
    return DASHBOARD

if __name__ == "__main__":
    app.run(debug=True, port=5000)
