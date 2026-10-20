# Management API

`/api/v1`, over the same HTTPS listener as everything else. JSON in and out; every response
carries `Cache-Control: no-store`. This is the API as built in P5: the directory,
authentication and the audit log. Applications, sessions and keys join it with the code
that owns them.

## Credentials and scopes

Every route needs a caller: from P6, a signed-in person's session (the dashboard, with a
CSRF token) or an OAuth access token, each carrying the scopes it was granted. Until then
nothing resolves a caller, and every route answers `401`. There is no other way in: no
bootstrap token, no key in a file, no setting. The one credential a cluster is born with is
root's password, made at genesis (`lugh init` on the first node) and shown once.

| Scope | Allows |
|---|---|
| `lugh:directory.read` | Reading users, groups, memberships, factors (never their secrets) and policies |
| `lugh:directory.write` | Creating, changing and removing users and groups, and who is in which |
| `lugh:credentials.write` | Enrolment links, and removing or resetting a user's factors |
| `lugh:policies.write` | Setting the assurance level, globally and per group |
| `lugh:audit.read` | Reading and verifying the audit log |

No token, or one that does not resolve: `401` with `WWW-Authenticate: Bearer realm="lugh"`,
limited by client address. A token without the route's scope: `403`. A caller is limited
to 120 requests at once and 600 a minute (`429` with `Retry-After`).

## Errors

One shape for every error:

```json
{ "error": { "code": "duplicate", "message": "the name alice is taken" } }
```

Branch on the code, which never changes; the message is for a person and never repeats a
secret.

| Status | Code | When |
|---|---|---|
| 400 | `invalid` | Not a JSON object, an unknown or mistyped field, a value out of bounds |
| 401 | `unauthorized` | No credential, or one that does not resolve |
| 403 | `forbidden` | The credential lacks the route's scope |
| 404 | `not_found` | No such endpoint, user, group, membership or factor |
| 405 | `method_not_allowed` | The path does not take that method |
| 409 | `duplicate` | A name or address another record has |
| 409 | `refused` | Understood and not allowed: the last factor, a link for someone enrolled |
| 412 | `changed` | `If-Match` is not the current version |
| 428 | `if_match_required` | A write to something that exists, without `If-Match` |
| 429 | `rate_limited` | Too many requests; see `Retry-After` |
| 503 | `busy` | Every work thread is taken and the queue is full; see `Retry-After` |
| 500 | `failed` | The store failed; nothing was changed |

A field the route does not know is refused, not ignored, so a misspelling is never a silent
no-op.

## Versions

A user or group carries its version as a strong `ETag`. `PATCH` and `DELETE` on one need
`If-Match` with the ETag last read (or `*` to skip the check); a stale one gets `412`, and
the client reads again. Policies are settings written whole with `PUT`, and memberships are
`PUT` and `DELETE` on the membership itself, so both are safe to repeat and take no version.

## Routes

| Method and path | Scope | Does |
|---|---|---|
| `GET /api/v1/users` | directory.read | Every user; `?name=` or `?email=` for one |
| `POST /api/v1/users` | directory.write | `{kind?, name, email, display_name?}`: `201`, `Location`, `ETag`. A person needs an address and starts not enrolled; a `service` needs neither |
| `GET /api/v1/users/{id}` | directory.read | One user |
| `PATCH /api/v1/users/{id}` | directory.write | `{name?, email?, display_name?, disabled?}`, with `If-Match` |
| `DELETE /api/v1/users/{id}` | directory.write | With `If-Match`: the user, their memberships, password and factors. Final |
| `GET /api/v1/users/{id}/groups` | directory.read | Their groups |
| `GET /api/v1/users/{id}/factors` | directory.read | Their factors: `id`, `kind`, `confirmed`, `created_at`, and `remaining` for recovery codes |
| `DELETE /api/v1/users/{id}/factors/{factor}` | credentials.write | One factor; `409 refused` for the last while policy needs one |
| `POST /api/v1/users/{id}/factors/reset` | credentials.write | Every factor gone and the user not enrolled, for one who lost them all |
| `POST /api/v1/users/{id}/enrolment` | credentials.write | A one-time enrolment link: `201 {token, expires_at}`, shown once, valid 72 hours, ending any before it |
| `GET /api/v1/groups` | directory.read | Every group; `?name=` for one |
| `POST /api/v1/groups` | directory.write | `{name, description?}` |
| `GET /api/v1/groups/{id}` | directory.read | One group |
| `PATCH /api/v1/groups/{id}` | directory.write | `{name?, description?}`, with `If-Match` |
| `DELETE /api/v1/groups/{id}` | directory.write | With `If-Match`: the group and its memberships |
| `GET /api/v1/groups/{id}/members` | directory.read | Its members, as users |
| `PUT /api/v1/groups/{id}/members/{user}` | directory.write | Adds them; `204` whether or not they were in it |
| `DELETE /api/v1/groups/{id}/members/{user}` | directory.write | Removes them; `404` if they were not |
| `GET /api/v1/policies` | directory.read | `{global, groups: [{group, acr}]}` |
| `PUT /api/v1/policies/global` | policies.write | `{acr}`: `urn:lugh:acr:pwd`, `mfa` or `phr` |
| `PUT /api/v1/policies/groups/{id}` | policies.write | `{acr}`, or `{acr: null}` to clear |
| `GET /api/v1/audit` | audit.read | `?from=` (default 1) and `?limit=` (default 100, at most 1000): `{entries, next}`, `next` null at the end |
| `GET /api/v1/audit/verify` | audit.read | Walks the whole chain: `{intact: true, entries}` or `{intact: false, problem}` |

Times are RFC 3339 in UTC. A factor's `id` is its kind and an instance (`totp-1a2b...`),
never its secret.

## Where it runs

Every route is a coroutine, spawned once the credential, the limits and the scope have
been checked in memory, so a refusal costs nothing. A handler suspends on the store, the
audit log or the hashing pool and holds no thread while it waits; a write to one table
waits only for writes to that table. At most 256 requests are in flight; past that the
answer is `503 busy`. Concurrent writes are safe: a name or address taken twice at once goes
to one writer, and the other gets `409 duplicate`.

## Not yet

- **Signing in** is P6: the enrolment link's token is redeemed by the sign-in pages, which
  set the password and enrol the TOTP factor.
- **Lists are whole.** A directory of a few thousand is one response. Paging arrives if a
  directory grows past that.
