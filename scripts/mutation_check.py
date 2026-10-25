"""Proves the tests actually test the security code.

For each mutation we break one security control, run the test-suite in a
subprocess, and REQUIRE it to fail. If a mutated build still passes, the
tests were not testing that control.

    python scripts/mutation_check.py
"""
import subprocess
import sys

MUTATIONS = {
    "authorize(): allow every action to everyone":
        "import trustvault.permissions as p; p._allowed_actions = lambda u, d, l: set(p.ALL_ACTIONS)",
    "authorize(): ignore revoked/expired grants":
        "import trustvault.permissions as p\n"
        "p._level = lambda db, u, d: 'owner' if d['owner_id']==u['id'] else (\n"
        "  (lambda r: r['level'] if r else None)(db.execute('SELECT level FROM grants WHERE doc_id=? AND user_id=?', (d['id'], u['id'])).fetchone()))",
    "authorize(): treat every grant as 'edit'":
        "import trustvault.permissions as p; p.LEVEL_ACTIONS['read'] = set(p.LEVEL_ACTIONS['edit'])",
    "authorize(): let admins download file contents":
        "import trustvault.permissions as p; p.ADMIN_ACTIONS.add('download')",
    "authorize(): return 403 instead of 404 for hidden documents":
        "import trustvault.permissions as p, flask\n"
        "o = flask.abort; p.abort = lambda c: o(403)",
    "audit: stop recording refused attempts":
        "import trustvault.audit as a; o = a.log\n"
        "a.log = lambda action, result='allowed', *x, **k: None if result == 'denied' else o(action, result, *x, **k)",
    "CSRF: disable the check":
        "import trustvault.auth as a; a.check_csrf = lambda: None\n"
        "import trustvault; ",
    "uploads: skip content (magic byte) validation":
        "import trustvault.validation as v; v._magic_ok = lambda e, d: True",
}

# CSRF's before_request captured the original function at create_app time, so patch via module attr lookup:
PRELUDE = "import sys; sys.path.insert(0, '.')\n"
RUN = "\nimport unittest; r = unittest.TextTestRunner(verbosity=0, stream=open('/dev/null','w')).run(unittest.defaultTestLoader.discover('tests', top_level_dir='.')); sys.exit(0 if r.wasSuccessful() else 1)\n"

if __name__ == "__main__":
    # sanity: clean build passes
    base = subprocess.run([sys.executable, "-c", PRELUDE + RUN]).returncode
    if base != 0:
        sys.exit("Baseline test-suite does not pass; fix that first.")
    survived = []
    for name, patch in MUTATIONS.items():
        rc = subprocess.run([sys.executable, "-c", PRELUDE + patch + RUN]).returncode
        print(("CAUGHT   " if rc != 0 else "SURVIVED ") + name)
        if rc == 0:
            survived.append(name)
    if survived:
        sys.exit(f"\n{len(survived)} mutation(s) survived: tests are missing coverage.")
    print("\nAll mutations caught.")
