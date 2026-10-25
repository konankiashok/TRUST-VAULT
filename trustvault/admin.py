from datetime import datetime, timedelta

from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from . import audit, auth, services
from .auth import roles_required
from .db import begin, get_db, now_iso

bp = Blueprint("admin", __name__, url_prefix="/admin")


def _alerts(db):
    out = []
    for r in db.execute(
        "SELECT actor_name, COUNT(*) c FROM audit_log WHERE result='denied' AND ts>? "
        "GROUP BY actor_name HAVING c>=5", (now_iso(timedelta(hours=-1)),)):
        out.append(f"Repeated refused attempts: {r['actor_name']} ({r['c']} in the last hour)")
    for r in db.execute(
        "SELECT actor_name, COUNT(*) c FROM audit_log WHERE action='download' AND result='allowed' "
        "AND ts>? GROUP BY actor_name HAVING c>=10", (now_iso(timedelta(minutes=-10)),)):
        out.append(f"Bulk downloads: {r['actor_name']} ({r['c']} in 10 minutes)")
    for r in db.execute(
        "SELECT a.actor_name, a.doc_id, COUNT(*) c FROM audit_log a "
        "JOIN grants g ON g.doc_id=a.doc_id AND g.user_id=a.actor_id AND g.revoked_at IS NOT NULL "
        "WHERE a.result='denied' AND a.ts>=g.revoked_at GROUP BY a.actor_name, a.doc_id"):
        out.append(f"Access attempted after revocation: {r['actor_name']} on {r['doc_id']} ({r['c']}x)")
    return out


@bp.get("/")
@roles_required("admin")
def dashboard():
    db = get_db()
    stats = {
        "users": db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"],
        "documents": db.execute("SELECT COUNT(*) c FROM documents WHERE deleted_at IS NULL").fetchone()["c"],
        "denied_24h": db.execute("SELECT COUNT(*) c FROM audit_log WHERE result='denied' AND ts>?",
                                 (now_iso(timedelta(hours=-24)),)).fetchone()["c"],
    }
    return render_template("admin_dashboard.html", alerts=_alerts(db), chain=audit.verify(), stats=stats)


@bp.get("/activity")
@roles_required("admin")
def activity():
    a = request.args
    def d(v):
        try:
            return datetime.strptime(v, "%Y-%m-%d") if v else None
        except ValueError:
            return None
    dfrom, dto = d(a.get("date_from")), d(a.get("date_to"))
    rows = get_db().execute(
        """SELECT * FROM audit_log WHERE (:u='' OR actor_name=:u COLLATE NOCASE)
           AND (:doc='' OR doc_id=:doc) AND (:act='' OR action=:act)
           AND (:res='' OR result=:res) AND (:df='' OR ts>=:df) AND (:dt='' OR ts<:dt)
           ORDER BY id DESC LIMIT 300""",
        {"u": (a.get("user") or "")[:64], "doc": (a.get("doc") or "")[:64],
         "act": (a.get("action") or "")[:40], "res": a.get("result") if a.get("result") in ("allowed", "denied") else "",
         "df": dfrom.strftime("%Y-%m-%d") if dfrom else "",
         "dt": (dto + timedelta(days=1)).strftime("%Y-%m-%d") if dto else ""}).fetchall()
    return render_template("audit.html", rows=rows, doc=None, title="Document activity", args=a, filters=True)


@bp.get("/permissions")
@roles_required("admin")
def permissions():
    rows = get_db().execute(
        "SELECT g.*, d.name AS doc_name, u.username AS grantee, b.username AS grantor "
        "FROM grants g JOIN documents d ON d.id=g.doc_id JOIN users u ON u.id=g.user_id "
        "JOIN users b ON b.id=g.granted_by ORDER BY g.id DESC LIMIT 300").fetchall()
    return render_template("admin_permissions.html", rows=rows)


@bp.route("/users", methods=["GET", "POST"])
@roles_required("admin")
def users():
    if request.method == "POST":
        try:
            uid = services.create_user((request.form.get("username") or "").strip(),
                                       request.form.get("password") or "", request.form.get("role"))
            audit.log("user_create", "allowed", user=g.user, target=request.form.get("username"),
                      detail=f"role={request.form.get('role')}")
            flash("User created.", "ok")
        except ValueError as e:
            flash(str(e), "error")
        return redirect(url_for("admin.users"))
    rows = get_db().execute("SELECT id, username, role, active, created_at FROM users ORDER BY id").fetchall()
    return render_template("admin_users.html", rows=rows)


@bp.post("/users/<int:user_id>/<state>")
@roles_required("admin")
def set_state(user_id, state):
    if state not in ("disable", "enable") or user_id == g.user["id"]:
        abort(400)
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    if not u:
        abort(404)
    db.execute("UPDATE users SET active=? WHERE id=?", (1 if state == "enable" else 0, user_id))
    if state == "disable":
        auth.destroy_user_sessions(user_id)  # takes effect immediately
    audit.log(f"user_{state}", "allowed", user=g.user, target=u["username"])
    flash(f"User {state}d.", "ok")
    return redirect(url_for("admin.users"))
