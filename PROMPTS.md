# PROMPTS.md

> **How this was built:** over a single day (not seven), with Claude (Anthropic) writing most of the code from my instructions.
> The commit history reflects that. Entries below are things that actually happened; I replaced nothing with polished fiction.
> **Before submitting: replace each `<commit>` with the real link after you push, and add your own entries if you hit other problems.**

## Reused prompts / context (the "how I work" part)

1. **Stage-1 spec prompt** (kept as the contract for everything after): roles (admin/owner/viewer), per-document grants, *one* `authorize()` used by every route, default deny, identical 404 for "forbidden" and "missing", visibility enforced inside SQL, no caching of permissions, encrypted blobs outside the web root, upload validation, append-only hash-chained audit with denials logged, admin view, tests proving user B cannot reach user A's documents.
2. **Standing rule I gave the tool:** "Cut features before cutting security. Tell me what you left out and why." That produced the NOT BUILT list in THREATS.md instead of half-working extras.
3. **Verification rule:** "Don't tell me it's secure. Prove it: write a test, then break the code and show the test fail." That produced `scripts/mutation_check.py`.

## Entries

### 2026-10-25 · Choosing a stack the tool could actually deliver
- **Asked:** a prompt to build the whole challenge in MERN using the Antigravity IDE.
- **Produced:** a very large single MERN spec (separate React app + Express API + JWT + Mongo).
- **Wrong:** it never asked what environment I had. On my laptop the tool did not produce working output, so the plan was unusable, and a JWT-plus-separate-frontend design is also harder to revoke immediately than server-side sessions. *(Edit: add your own specifics of what failed.)*
- **Instead:** moved to a single Flask service with server-side sessions, which makes "revoke = next request fails" trivial. Commit: `<commit>`

### 2026-10-25 · Alert for "access after revocation" silently never fired (audit / access control)
- **Asked:** an admin alert that flags refused attempts on a document made after a user's access was revoked.
- **Produced:** a SQL join comparing `audit.ts > grant.revoked_at`.
- **Wrong:** timestamps have one-second resolution, so a user retrying in the same second as the revoke was missed. The first test run failed (`test_T22`).
- **Instead:** changed to `>=` and kept the test. Commit: `<commit>`

### 2026-10-25 · First audit design was forgeable (audit trail)
- **Asked:** a tamper-evident audit log.
- **Produced:** a plain SHA-256 hash chain plus triggers blocking UPDATE/DELETE.
- **Wrong:** anyone able to edit the database file can drop the trigger, change a row, and **recompute every hash**, because plain SHA-256 needs no secret. The chain proved nothing against exactly the attacker the brief worries about. My own review of the design found this before the first test existed.
- **Instead:** HMAC-SHA256 with a key derived from an environment secret that is not in the database, plus contiguous-id and `sqlite_sequence` checks for tail truncation. Added `test_T20b`, which edits a row and recomputes the whole chain with plain SHA-256 and requires verification to still fail. Commit: `<commit>`

### 2026-10-25 · Authorization: nothing wrong found, so here is how I checked (access control)
- **Asked:** a single `authorize()` gate and tests for IDOR.
- **Produced:** `permissions.py` with a level->action table, admin limited to metadata, 404/403 split.
- **Wrong:** nothing that I could find in the final code. I do not take that on faith: `scripts/mutation_check.py` applies eight mutations (allow-all, ignore revocation, read treated as edit, admin can download, 403 instead of 404, stop auditing denials, disable CSRF, skip magic-byte check) and requires the suite to fail for each. All eight were caught. Also `test_T05` walks every route in `url_map` unauthenticated. Commit: `<commit>`

### 2026-10-25 · Environment slip: wrong project layout (not security)
- **Asked:** scaffold the project directories in one shell command.
- **Produced:** a command using `{a,b,c}` brace expansion; the sandbox shell was `/bin/sh`, which doesn't expand it, so it created a directory literally named `{trustvault`, and later `cd` failed and files landed in the wrong place.
- **Caught:** by listing the directory after the "done" message rather than trusting it.
- **Instead:** recreated the layout explicitly and moved the files. Commit: `<commit>`

### 2026-10-25 · Test written against the wrong library attribute (not security)
- A cookie-flag test used `cookie.samesite`; the library attribute is `same_site`. Test error, not product error; fixed in the test. Commit: `<commit>`
