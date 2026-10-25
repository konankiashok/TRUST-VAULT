# TrustVault

Secure document sharing where the wrong person cannot read a file, and the record proves who did.
Flask + SQLite, server-rendered. Single deployable service.

**Live URL:** `<paste your Render URL here>`

## Demo accounts (seeded; demo only, change before real use)

| Role   | Username | Password            | Notes |
|--------|----------|---------------------|-------|
| admin  | `admin`  | `Admin-Demo-2026!`  | sees metadata, activity, permission history, alerts, chain verification; **cannot read file contents** |
| owner  | `alice`  | `Alice-Demo-2026!`  | owns *salary-letter-carol.txt* (shared read with carol) and *q3-audit-notes.txt* (shared with nobody) |
| owner  | `bob`    | `Bob-Demo-2026!`    | owns *customer-contract.txt* (read→dave) and *drawing-spec.txt* (edit→dave) |
| viewer | `carol`  | `Carol-Demo-2026!`  | can read only Alice's salary letter |
| viewer | `dave`   | `Dave-Demo-2026!`   | can read Bob's contract, edit Bob's drawing spec |

Try: log in as `carol`, open Alice's other document by URL -> 404. Log in as `alice`, revoke Carol -> Carol's next request fails.

## Run locally

```bash
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
SEED_ON_START=1 python wsgi.py                          # http://127.0.0.1:5000
python -m unittest discover -s tests -t .               # 40 tests
python scripts/mutation_check.py                        # proves the tests catch removed security checks
```
(Windows PowerShell: `$env:SEED_ON_START="1"; python wsgi.py`)

In dev, secrets are generated into `./data/`. Data lives in `./data/` (SQLite file + encrypted blobs).

## Deploy (Render, from a clean clone)

1. Push this repo to GitHub.
2. Render dashboard -> **New -> Blueprint** -> pick the repo. It reads `render.yaml`.
3. Wait for the build. Open the service URL; log in with a demo account above.

`render.yaml` sets `TV_ENV=production`, generates `SECRET_KEY` and `FILE_ENC_KEY`, and seeds on first boot.

**Free-plan caveat (be honest in the demo):** Render's free plan has no persistent disk, so the database and uploaded files reset on each restart/redeploy and the seed data is recreated. For anything real, attach a persistent disk, set `DATA_DIR` to its mount path, and set `SEED_ON_START=0` after the first boot.

### Environment variables

| Var | Purpose |
|---|---|
| `TV_ENV=production` | Secure cookies, HSTS, refuses to start without the two secrets |
| `SECRET_KEY` | Signs the (login-form-only) Flask session cookie |
| `FILE_ENC_KEY` | Root secret: derives the file-key-wrapping key and the audit HMAC key. **Losing it makes files unreadable; changing it breaks audit verification.** |
| `DATA_DIR` | Where the SQLite DB and encrypted blobs live |
| `TRUST_PROXY=1` | Trust one `X-Forwarded-*` hop (needed on Render for correct client IPs in the audit) |
| `SEED_ON_START=1` | Seed demo users/docs if the database has no users |

## Layout

```
trustvault/permissions.py   the ONE authorization function (read this first)
trustvault/audit.py         HMAC hash-chained append-only audit log + verifier
trustvault/auth.py          server-side sessions, CSRF, route guards
trustvault/storage.py       AES-256-GCM envelope encryption of files
trustvault/validation.py    upload validation
trustvault/views.py, admin.py, services.py, db.py (schema + triggers), seed.py
tests/                      40 tests, each mapped to a THREATS.md entry
scripts/mutation_check.py   removes security controls and requires the tests to fail
docs: API.md  THREATS.md  WRITEUP.md  PROMPTS.md
```
