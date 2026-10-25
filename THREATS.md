# THREATS.md

Format: **threat** -> what I did -> test (`tests/test_security.py`). "ACCEPTED" and "NOT BUILT" entries are deliberate and explained.

## Access control

| # | Threat | Mitigation | Test |
|---|---|---|---|
| 1 | **IDOR**: guess/replay another user's document URL (view, download, edit, delete, share, audit) | One `authorize(user, doc_id, action)` is called by every document route; default deny; owner is read from the DB, never from the request | T01, T08 |
| 2 | **Enumeration**: telling "exists but forbidden" from "doesn't exist" | Both return an identical 404 page; UUIDv4 ids; malformed ids behave the same | T02 |
| 3 | **Search/list leakage** (filter after fetch, wildcard, owner/category filters) | Visibility is part of the SQL `WHERE` (owner OR active grant OR admin-metadata); `LIKE` wildcards are escaped | T03, T04 |
| 4 | **SQL injection** | Parameterised queries everywhere; no string-built SQL | T04 |
| 5 | **Forgotten check on a route** | Test walks `app.url_map` unauthenticated; `mutation_check.py` removes controls and requires failures | T05, mutation script |
| 6 | **Privilege creep via grant levels** (reader edits/deletes/shares) | Level -> action table in `permissions.py`; delete/share/audit are owner-only | T06, T07 |
| 7 | **Grant on one doc opening another** / revoking another doc's grant | Grants are keyed by `(doc_id, user_id)`; revoke query requires `grant.doc_id == <id>` | T08, T10 |
| 8 | **Admin overreach** (admin reads everything) | Admin gets metadata + activity only; reading content needs an explicit grant like anyone | T09, T21 |
| 9 | **Mass assignment** (`owner_id`, `role` in forms) | Handlers read named fields only; owner is always `g.user` | T28 |
| 10 | **Viewer uploads / role bypass** | `roles_required("owner")` on upload; role loaded from DB each request | T27 |

## Revocation

| # | Threat | Mitigation | Test |
|---|---|---|---|
| 11 | **Revoked user keeps access** (cached perms, long-lived tokens, share links) | Sessions are opaque server-side rows; permissions are re-read from the DB on **every** request; there are no signed URLs or tokens that grant document access, and files are only streamed through `authorize()` | T11, T12 |
| 12 | **Expired grant still works** | Expiry is part of the grant lookup | T13 |
| 13 | **Disabled/fired user keeps a session** | Disabling deletes their sessions in the same transaction; login refused | T14 |
| 14 | **Stolen cookie after logout** | Logout deletes the server row; absolute (8 h) and idle (60 min) timeouts | T15 |
| 15 | **Race: revoke vs. download in flight** | `BEGIN IMMEDIATE` is taken before the permission check, so check + read + audit are atomic w.r.t. a revoke. **ACCEPTED:** bytes already delivered cannot be recalled, and no system can; the audit proves they were taken | design |

## Audit trail

| # | Threat | Mitigation | Test |
|---|---|---|---|
| 16 | **Refused attempts not recorded** | Every denial (incl. nonexistent ids, unauthenticated, CSRF failures, login failures, rejected uploads) is logged | T16 |
| 17 | **Quietly editing/deleting history** | Layer 1: DB triggers abort `UPDATE`/`DELETE` on `audit_log`; no code path edits it. Layer 2: each row stores `HMAC(key, prev_hash + row)`; the key is derived from `FILE_ENC_KEY` and is **not in the database**, so someone with only the DB file can't recompute a valid chain. Layer 3: ids must be contiguous and match `sqlite_sequence`, catching tail truncation. Admin page recomputes the chain on every load | T18-T20b |
| 18 | **Action without a record** | Audit insert is in the same transaction as the action; if it fails the request rolls back | design |
| 19 | **ACCEPTED: attacker with the DB file *and* the server's env key** | Can forge a valid chain. Mitigations I'd add with more time: ship the head hash to an external append-only store (the admin page shows the head to record by hand), or sign with a KMS/HSM key | none |
| 20 | **ACCEPTED: SQLite triggers can be dropped by whoever owns the file** | With Postgres I'd give the app role INSERT+SELECT only on the audit table; documented, not built | T19 shows tamper is still detected |

## Authentication and sessions

| # | Threat | Mitigation | Test |
|---|---|---|---|
| 21 | **Brute force** | Lockout after 5 failures / 15 min per username (30 per IP); scrypt hashes. **ACCEPTED:** lockout lets an attacker lock a known user out (DoS); I chose that over unlimited guessing | T33 |
| 22 | **Username enumeration** (messages, timing) | Identical error and status; a dummy hash is verified for unknown users | T34 |
| 23 | **CSRF** | Per-session token on every POST (login has its own); `SameSite=Strict` cookie | T31, T32 |
| 24 | **Session theft/fixation** | New random 256-bit token each login; only its SHA-256 is stored; `HttpOnly`, `Secure` (production), `SameSite=Strict`; garbage cookies rejected | T35, T36 |
| 25 | **XSS via filenames/titles** | Jinja autoescape; strict CSP (`default-src 'none'`, no inline script/style); no JS at all | T37 |
| 26 | **Clickjacking / caching of sensitive pages** | `X-Frame-Options: DENY`, CSP `frame-ancestors 'none'`, `Cache-Control: no-store` | T35 |

## Files

| # | Threat | Mitigation | Test |
|---|---|---|---|
| 27 | **Spoofed type / polyglot / script upload** | Extension allow-list + magic-byte check + (for docx/xlsx) zip structure & zip-bomb limits; browser MIME ignored; served as `attachment` + `nosniff` with a server-chosen MIME | T23, T24, T29 |
| 28 | **Path traversal** | Storage name is `<uuid>.<version>.bin` from the server; user filename only ever sanitised display text | T26 |
| 29 | **Oversize / DoS** | 5 MB limit (6 MB request cap) | T25 |
| 30 | **Disk/backup theft** | Per-file AES-256-GCM key, wrapped by a master key that is not on disk with the data; ciphertext bound to the document id (AAD) | T29 |
| 31 | **Replacing a file with a different type** | Replacement must match the stored MIME | T30 |

## Deliberately not built / accepted (honest list)

- **NOT BUILT: external sharing links, document versions UI/restore, retention/purge, folders/groups.** Time. Grants are per-document; "categories" are labels only (no inheritance, so no "access to a folder reveals forty files" failure). Soft-deleted files stay encrypted on disk; replaced versions are crypto-shredded (their key is overwritten) but there is no restore.
- **NOT BUILT: MFA, password reset, email.** Admin creates users; there is no self-service recovery.
- **NOT BUILT: AI suggestions** (so the "machine must never widen access" rule is satisfied trivially: no AI in the product).
- **NOT BUILT: malware scanning.** Files are never rendered by the server, only downloaded as attachments.
- **ACCEPTED: owners can probe whether a username exists** via the grant form (needed to name a person).
- **ACCEPTED: single-node SQLite** (one writer). Fine for this scale; Postgres for more.
- **ACCEPTED: no general rate limiting** beyond login; put a CDN/WAF in front in production.
- **ACCEPTED: free-tier demo resets its data on restart** (see README). The audit chain resets with it; a real deployment needs a persistent disk or database.
- **ACCEPTED: seeded demo passwords are public** by design for the judges.
- **ACCEPTED: host compromise** (reads env keys + blobs) defeats at-rest encryption; a KMS would raise the bar.
