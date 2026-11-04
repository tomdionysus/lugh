# Management API

`/api/v1`, over the same HTTPS listener as everything else. JSON in and out; every response
carries `Cache-Control: no-store`. This is the API as built in P5: the directory,
authentication and the audit log. Applications, sessions and keys join it with the code
that owns them.

## Credentials and scopes

Every route needs a caller. Today that is a signed-in Lugh session: the `__Host-lugh_session`
cookie the sign-in pages set (`/signin`). A request through a session that may change
anything (any method but `GET` and `HEAD`) also carries the session's CSRF token in
`X-CSRF-Token`; `GET /api/v1/me` gives it. OAuth access tokens join sessions with the token
endpoint (P6). There is no other way in: no bootstrap token, no key in a file, no setting.
The one credential a cluster is born with is root's password, made at genesis (`lugh init` on
the first node) and shown once, and it opens a session only through the sign-in pages, where
root's first sign-in goes straight to enrolling a second factor.

A caller's scopes are those its groups grant (`/api/v1/groups/{id}/scopes`), read when the
session starts and again every minute, so a change to someone's groups reaches their session
within a minute; so does disabling or removing them, which ends it.

| Scope | Allows |
|---|---|
| `lugh:directory.read` | Reading users, groups, memberships, factors (never their secrets) and policies |
| `lugh:directory.write` | Creating, changing and removing users and groups, and who is in which |
| `lugh:credentials.write` | Enrolment links, and removing or resetting a user's factors |
| `lugh:policies.write` | Setting the assurance level, globally and per group, and which scopes each group grants |
| `lugh:audit.read` | Reading and verifying the audit log |
| `lugh:apps.write` | Registering, changing and removing applications, who may use them, their roles and their secrets |
| `lugh:keys.write` | Rotating a token signing key |

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
| `GET /api/v1/me` | any caller | `{user, scopes, session}`: who the caller is, what it holds, and for a session its `acr`, `auth_time` and `csrf_token` |
| `GET /api/v1/users` | directory.read | Every user; `?name=` or `?email=` for one |
| `POST /api/v1/users` | directory.write | `{kind?, name, email, display_name?, given_name?, family_name?}`: `201`, `Location`, `ETag`. A person needs an address and starts not enrolled; a `service` needs neither. `given_name` and `family_name` are the OIDC claims and LDAP's `givenName` and `sn`; neither is required, since not every name has two parts |
| `GET /api/v1/users/{id}` | directory.read | One user. `posix_number` appears once LDAP has allocated one |
| `PATCH /api/v1/users/{id}` | directory.write | `{name?, email?, display_name?, given_name?, family_name?, disabled?}`, with `If-Match` |
| `DELETE /api/v1/users/{id}` | directory.write | With `If-Match`: the user, their memberships, password and factors. Final |
| `GET /api/v1/users/{id}/groups` | directory.read | Their groups |
| `GET /api/v1/users/{id}/app-passwords` | directory.read | Their app passwords: `id`, `name`, `scopes`, `networks`, `created_at`; never the password |
| `POST /api/v1/users/{id}/app-passwords` | credentials.write | `{name, scopes?, networks?}`: a new app password, `201` with `password` shown this once. `scopes` defaults to `lugh:directory.read`; at most 32 per user |
| `DELETE /api/v1/users/{id}/app-passwords/{app_password}` | credentials.write | Revokes it alone |
| `GET`, `POST /api/v1/me/app-passwords`, `DELETE /api/v1/me/app-passwords/{app_password}` | any caller | The same for the caller's own, never with a scope the caller does not hold |
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
| `GET /api/v1/groups/{id}/scopes` | directory.read | The scopes the group grants its members: `{scopes}`, with an `ETag` (`"0"` for a group never granted anything) |
| `PUT /api/v1/groups/{id}/scopes` | policies.write | `{scopes: [...]}`, the whole set, with `If-Match`: each scope one Lugh can grant (Lugh's own, OIDC's, an application's `<prefix>:<name>`, or a topic scope `lir:pub\|sub\|retain:<filter>`), stored sorted and once each, at most 256. A user's scopes are the union over their groups |
| `GET /api/v1/scopes` | directory.read | `{lugh, oidc}`: the scopes Lugh itself defines. Applications' arrive with applications |
| `GET /api/v1/policies` | directory.read | `{global, groups: [{group, acr}]}` |
| `PUT /api/v1/policies/global` | policies.write | `{acr}`: `urn:lugh:acr:pwd`, `mfa` or `phr` |
| `PUT /api/v1/policies/groups/{id}` | policies.write | `{acr}`, or `{acr: null}` to clear |
| `GET /api/v1/apps` | directory.read | Every application not removed: `{apps}` |
| `POST /api/v1/apps` | apps.write | Registers one: `201`, `Location`, `ETag`, and `client_secret` when it uses `client_secret_basic`, shown this once and kept only as a hash. The fields are below |
| `GET /api/v1/apps/{client_id}` | directory.read | One application, never its secret |
| `PATCH /api/v1/apps/{client_id}` | apps.write | Any field but `kind` and `scope_prefix`, which never change, with `If-Match`; `enabled: false` disables it |
| `DELETE /api/v1/apps/{client_id}` | apps.write | With `If-Match`. Final: the application stays as a tombstone, so its `client_id` and `scope_prefix` are never used again |
| `PUT`, `DELETE /api/v1/apps/{client_id}/access/{group}` | apps.write | Whether the group's members may sign in to it; answers the application |
| `PUT /api/v1/apps/{client_id}/roles/{group}` | apps.write | `{roles: [...]}`: the application's role names the group maps to, for its audience only; empty clears |
| `POST /api/v1/apps/{client_id}/secret` | apps.write | A new client secret, shown once; the one before works for 24 hours more (`previous_secret_expires_at`) |
| `GET /api/v1/keys` | directory.read | The token signing keys, never their private parts: `kid`, `algorithm`, `created_at`, `signing_from`, `retired_at` |
| `POST /api/v1/keys/rotate` | keys.write | `{algorithm}`, `ES256` or `EdDSA`: a new key, published now and signing in an hour; the one it replaces stays published two hours more. Keys also rotate by themselves after 90 days |
| `GET /api/v1/audit` | audit.read | `?from=` (default 1) and `?limit=` (default 100, at most 1000): `{entries, next}`, `next` null at the end |
| `GET /api/v1/audit/verify` | audit.read | Walks the whole chain: `{intact: true, entries}` or `{intact: false, problem}` |

Times are RFC 3339 in UTC. A factor's `id` is its kind and an instance (`totp-1a2b...`),
never its secret.

## Applications

An application is an OAuth client an administrator registered (`docs/architecture.md`,
"Applications"). Its fields, as `POST` takes them and every answer shows them:

| Field | Is |
|---|---|
| `client_id` | Made by Lugh: `app_` and 22 random characters. Never used again |
| `name`, `icon_uri`, `home_uri` | Shown on the sign-in and consent pages; the URIs are https |
| `kind` | `web`, `spa`, `native`, `service` or `api`. Never changes |
| `scope_prefix` | An `api`'s: its scopes are `<prefix>:<name>`, and its audience is the prefix. Lower-case letters, digits and `-`; not `lugh`. Never changes, never reused |
| `client_authentication` | `none` for `spa` and `native` (they use PKCE); `private_key_jwt` (with `jwks`, public keys only), `tls_client_auth` (with `tls_client_auth_subject_dn` or `tls_client_auth_thumbprint`), or `client_secret_basic` where `oauth.allow_client_secrets` is on, for the rest |
| `redirect_uris`, `post_logout_redirect_uris`, `backchannel_logout_uri` | Matched exactly. https only, except `http://127.0.0.1` and `http://[::1]` for a `native` app. Only for an app with `authorization_code` |
| `grant_types` | Of `authorization_code`, `refresh_token`, `urn:ietf:params:oauth:grant-type:device_code` and `client_credentials`, as the kind allows: `web` the first two and the last; `spa` the first two; `native` the first three; `service` and `api` the last |
| `scopes` | What it may ask for on a user's behalf |
| `audiences` | Its access tokens' `aud`: `lugh`, or a registered `api`'s prefix |
| `client_scopes` | What it holds itself, calling with `client_credentials` |
| `access`, `roles` | Set through their own routes, above |
| `acr`, `max_age` | The least assurance it needs, and how old a sign-in may be (seconds; 0 for any) |
| `first_party`, `opaque_access_tokens`, `sender_constraint` | Skip consent; opaque handles rather than JWTs; `none`, `dpop` or `mtls` |
| `lifetimes` | `{access_token, id_token, refresh_idle, refresh_absolute}` in seconds: 300, 300, a day and 30 days unless set |
| `enabled` | False refuses it everywhere |

An application's scope, or an audience, is accepted only once an `api` with its prefix is
registered; so is a group's grant of one.

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
