# API reference: who may call what

All routes are server-rendered HTML. Every state-changing request (POST) requires a CSRF token
(`csrf_token` form field or `X-CSRF-Token` header) tied to the caller's session. All document routes go through
`permissions.authorize()`; refusals are audited. "No access" returns the same `404` as "does not exist".

Definitions: **owner** = the user who uploaded the document. **read/edit grantee** = user with an active (not revoked, not expired) grant.

| Method & path | Who is allowed | Notes |
|---|---|---|
| `GET /login` | anyone | sets a login CSRF token |
| `POST /login` | anyone | 5 failures/15 min per username (and 30 per IP) -> `429`; generic error |
| `POST /logout` | any signed-in user | deletes the server-side session |
| `GET /` | anyone | redirects |
| `GET /documents` | any signed-in user | search `q`, `owner`, `category`, `date_from`, `date_to`. Scoped **in SQL** to own + granted docs. Admin sees all **metadata** |
| `POST /documents/upload` | role `owner` only | owner is forced to the caller; validated type/size/magic bytes; encrypted at rest |
| `GET /documents/<id>` | owner, read/edit grantee, admin (metadata only) | audited as `view` |
| `GET /documents/<id>/download` | owner, read/edit grantee. **Not admin** | streams decrypted bytes, `Content-Disposition: attachment`, `nosniff` |
| `POST /documents/<id>/edit` | owner, edit grantee | rename/category; optional same-type content replacement (new version) |
| `POST /documents/<id>/delete` | owner only | soft delete |
| `POST /documents/<id>/grants` | owner only | `username`, `level` (`read`/`edit`), optional `expires_days` (1-365) |
| `POST /documents/<id>/grants/<gid>/revoke` | owner only | grant must belong to `<id>`; effective on the next request |
| `GET /documents/<id>/audit` | owner, admin | per-document activity incl. refused attempts |
| `GET /admin/` | admin | alerts, chain verification (recomputed on every load), totals |
| `GET /admin/activity` | admin | filter by user, document, action, result, date |
| `GET /admin/permissions` | admin | every grant ever made, with grantor and revocation |
| `GET /admin/users`, `POST /admin/users` | admin | list / create (password >= 10 chars) |
| `POST /admin/users/<id>/disable`, `.../enable` | admin (not on self) | disable also deletes that user's sessions immediately |
| `GET /static/*` | anyone | CSS only |

Status codes: `302` redirect to login when unauthenticated; `400` bad/missing CSRF; `403` visible but not permitted (e.g. a reader trying to delete, or any non-admin on `/admin/*`);
`404` not found *or* not visible to you; `413` file > 5 MB; `429` login lockout.
