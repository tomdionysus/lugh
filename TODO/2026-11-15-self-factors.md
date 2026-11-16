# A person's own factors, after enrolment

`docs/architecture.md`, "Adding and removing factors": adding or removing a factor requires re-authenticating with an existing
factor, is audited, and notifies the user. P11's plan named adding a key after enrolment and left it open.

## the maintainer's rulings (2026-11-15)

- An API now, `/api/v1/me/factors`; P7's dashboard gives it its pages. No server-rendered `/signin/factors`.
- A sudo window: proving an existing factor (a WebAuthn assertion or a TOTP code; never the password alone, never a recovery code)
  marks the session re-authenticated for 10 minutes. Audited.
- Every change audited now; notifying the user waits on principal events over Lir (`2026-11-15-principal-events.md`).

## The routes

Every one only through the person's own signed-in session (a cookie, with its CSRF token on a change), never an application
holding a token: as `/api/v1/me/password`. A change outside the window is `403 reauthentication_required`.

| Route | Window | What |
|---|---|---|
| `GET /api/v1/me/factors` | no | The factors, as `/api/v1/users/{id}/factors` shows them |
| `POST /api/v1/me/webauthn/options` `{"purpose": "reauthenticate" \| "register"}` | register: yes | A ceremony's options, the challenge bound to the session |
| `POST /api/v1/me/reauthenticate` `{"code"}` or `{"webauthn": {...}}` | no | Opens the window: `{"until"}` |
| `POST /api/v1/me/factors/totp` | yes | A new unconfirmed TOTP secret, shown once: `{"id", "secret", "uri"}` |
| `POST /api/v1/me/factors/totp/{factor}/confirm` `{"code"}` | yes | Confirms it with a code from it |
| `POST /api/v1/me/factors/webauthn` `{"name", "challenge", "client_data", "attestation_object"}` | yes | Registers a credential |
| `PATCH /api/v1/me/factors/{factor}` `{"name"}` | yes | Renames a WebAuthn credential |
| `DELETE /api/v1/me/factors/{factor}` | yes | Removes one, under the last-factor rule |
| `POST /api/v1/me/factors/recovery` | yes | Ten new recovery codes, replacing the old, shown once |

The WebAuthn routes and purposes exist only where WebAuthn is offered (`oauth.issuer` set); elsewhere they are 404.

## Steps

| ID | Step |
|---|---|
| S1 | `session::Reauthentications`: the window, by sid, in memory, on the injected time. A restart closes every window, which fails closed. Bounded by the live sessions; expired entries pruned as new ones are made |
| S2 | `Authenticator::reauthenticate_totp` and `reauthenticate_webauthn`: a code or an assertion for a signed-in user, with the sign-in's back-off and audit (`reauth.totp.*`, `reauth.webauthn.*`). A code is refused where the user's policy is `phr` |
| S3 | `Factors::webauthn_rename` |
| S4 | `api::FactorRoutes`, the routes above, wired in `tools/lugh_node.cpp` with the one `Challenges` the pages use |
| S5 | Tests: S1 on stepped time; S2 over the memory store; the routes over HTTP; on the real node, a second TOTP factor added and the first removed, and a second passkey added after enrolment |
| S6 | `docs/api.md`, `docs/architecture.md` |
