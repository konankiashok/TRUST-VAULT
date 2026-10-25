# Write-up

## What I built
TrustVault: Flask + SQLite, server-rendered, one deployable service. Admin / owner / viewer roles; upload with validation; per-document read/edit grants to named users with optional expiry; owner grant/revoke; search by name, owner, category, date; encrypted storage; a hash-chained audit trail covering uploads, views, downloads, edits, deletes, grants, revokes, logins and **every refused attempt**; an admin area (activity filters, permission history, user management, alerts, live chain verification); 40 automated tests plus a mutation script.

## Permission model, in my own words
There is one rule-holder, `authorize(user, doc_id, action)`. A document belongs to its uploader (**owner**), who can do everything to it. Anyone else gets access only through a **grant** the owner made to them by name: `read` lets them view and download, `edit` adds editing. Only the owner can delete, share, or see the document's activity. Folders/categories are labels and grant nothing, so there is no inheritance to leak. The **admin** runs the system but is deliberately *not* a super-reader: they see metadata, activity and permission history, and cannot open file contents unless an owner grants them access like anyone else. Anything you can't see answers `404` (identical to "doesn't exist"); anything you can see but can't do answers `403`. The rule is default-deny and every refusal is written to the audit log.

## Immediate revocation, and what it costs
Nothing that grants document access is ever handed to the browser: no signed URLs, no JWT permissions, no share tokens. The browser holds only an opaque session id; on **every** request the server re-reads the session, the user (still active? role?) and the grant from the database. So revoking, expiring, downgrading or disabling takes effect on the next request. Cost: a database read on every request and no stateless scaling; I accepted that. Bytes already downloaded cannot be recalled, but the audit shows who took them.

## How files and the audit are protected
Files live outside any web path under random names, each encrypted with its own AES-256-GCM key, wrapped by a master key that comes from the environment, never the database. The audit log is append-only (DB triggers), hash-chained with HMAC using a key that is not in the database, contiguity-checked, and recomputed on every admin dashboard load. Honest limit: someone with both the database file **and** the server's secret can forge it; an external anchor (or KMS signing) is the next step (THREATS #19).

## What I deliberately did not build
External share links, version history/restore, retention/purge, folders/groups, MFA, password reset, malware scanning, the AI "who should see this" suggester, rate limiting beyond login. Reasons are in THREATS.md. I preferred a smaller system whose permission model I can fully prove to a bigger one with a hole in it.

## How I used AI, and where it was wrong
Claude wrote most of the code from my specification (PROMPTS.md). Real problems: an unusable first stack choice for my environment; an audit alert that silently never fired (timestamp resolution); a first audit-chain design that was forgeable by anyone who could edit the DB file; a scaffolding command that failed silently. I found them by running tests, reading the design critically and listing directories instead of trusting "done". I could not find an authorization error, so I attacked my own code with `scripts/mutation_check.py` (eight deliberately broken builds, all caught).

## What is unfinished
- Built in one day, not seven; the commit history reflects that.
- The demo deployment (free tier) loses data on restart; the audit chain resets with it.
- Everything under "Deliberately not built" above.
- I have not had an independent person attack the deployed system; the tests are my own.
