# OAuth 2 and OpenID Connect

What Lugh does as an authorisation server, for someone writing an application against it or
running it. The design and why it is so are in `TODO/2026-11-04-oauth.md`; the routes that
register applications are in `docs/api.md`. `lugh_client` will be written from this document.

## Turning it on

Nothing here is served until `oauth.issuer` is set. Without it the node warns and serves the
sign-in pages and the API alone.

| Setting | Is |
|---|---|
| `oauth.issuer` (`--oauth-issuer`, `LUGH_OAUTH_ISSUER`) | The issuer, an https URL with no query, fragment or trailing `/` |
| `oauth.allow_client_secrets` | Whether an application may use `client_secret_basic`. Off by default |
| `mtls.listen.port` (`--mtls-listen-port`, `LUGH_MTLS_LISTEN_PORT`) | A second listener that asks for client certificates, for `tls_client_auth` and tokens bound to a certificate. 0 for none |
| `mtls.tls.ca` | The CA a client certificate must chain to for its subject to name an application |
| `oauth.outbound_ca` | The roots an application's certificate must chain to when Lugh posts to it; the system's when not set. It changes the roots, never whether they are checked |

## The endpoints

| Route | Is |
|---|---|
| `GET /.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | The metadata (OIDC Discovery, RFC 8414) |
| `GET /oauth2/jwks` | The public signing keys |
| `GET /oauth2/authorize` | The authorisation request; on to sign-in or consent if needed |
| `POST /oauth2/par` | A pushed authorisation request (RFC 9126); the `request_uri` lives 60 seconds and is used once |
| `POST /oauth2/token` | `authorization_code` with PKCE, `refresh_token`, the device code, `client_credentials` |
| `POST /oauth2/device`, `/signin/device` | The device grant (RFC 8628) and where its user approves it |
| `POST /oauth2/revoke` | A refresh token's family, or an access token (RFC 7009) |
| `POST /oauth2/introspect` | Whether a token is active, and its claims (RFC 7662), for the client that holds it or an `api` among its audiences |
| `GET`, `POST /oauth2/userinfo` | The person's claims, for an access token with `openid` |
| `GET`, `POST /oauth2/logout` | RP-initiated logout |

## An authorisation request

Only an administrator registers an application. `redirect_uri` must match a registered one
exactly; a `native` app's `http://127.0.0.1` and `http://[::1]` may differ in the port (RFC
8252). PKCE with `S256` is required of everyone, and `nonce` with `openid`. `prompt`, `max_age`
and `acr_values` are honoured.

A request whose client or redirect URI cannot be trusted is refused on a page of Lugh's and is
never sent anywhere. Every other refusal goes back to the client with its `state` and `iss` (RFC
9207).

A request with no good enough session goes through the sign-in pages and resumes. Only members
of the groups the application allows get a code. A third-party application is consented to once
per set of scopes; a first-party one is not asked about.

**Coming back.** A plain request is answered with a `303`. When a form led here, a consent
answered or a sign-in finished, the answer is a page that goes on by itself and carries a link,
since `form-action 'self'` covers where a form's answer redirects. A client sees the same request
to its redirect URI either way.

Codes live 60 seconds, are redeemed once, and only on the node that made them.

## Client authentication

| `client_authentication` | For |
|---|---|
| `none` | `spa` and `native`: public, with PKCE |
| `private_key_jwt` | Any confidential client; a replayed assertion is refused |
| `tls_client_auth` | Through `mtls.listen.port`, by subject DN or thumbprint |
| `client_secret_basic` | Only where `oauth.allow_client_secrets` is on |

## Tokens

Signing keys are ES256 and EdDSA. A new key is published an hour before it signs, and the one it
replaces stays published two hours after. Keys rotate by themselves after 90 days.

**Access tokens** are JWTs of RFC 9068 (`typ` `at+jwt`): `iss`, `sub`, `aud`, `client_id`, `exp`,
`iat`, `nbf`, `jti`, `scope`, and for a person `acr`, `amr`, `auth_time` and `sid`. The audiences
are the application's, or its own `client_id` if it registered none. A client acting for itself
has its `client_id` as `sub`. Scopes are cut to what the audiences can use. A token verifier
needs the JWKS and nothing else from Lugh.

An application registered with `opaque_access_tokens` gets a random handle (`lo_...`) in its place,
which says nothing to anyone but Lugh. A resource server reads it at `/oauth2/introspect`, which
answers the same claims; it is good at userinfo, and it is bound, revoked and expires as a JWT is.
`/api/v1` takes JWTs only.

**ID tokens** (`typ` `JWT`): `iss`, `sub`, `aud`, `azp`, `exp`, `iat`, `auth_time`, `nonce`, `acr`,
`amr`, `sid`, `at_hash`, the claims `profile`, `email` and `groups` allow, and the application's
roles for the person's groups. Role mappings appear in the ID token and userinfo, not in access
tokens.

**Refresh tokens** need `offline_access`. They are single use: each refresh gives a new one, and
using an old one ends the whole family. A family ends with the session it came from. A refresh
may narrow the scopes and never widens them, and gives no new ID token.

**Lifetimes**, per application: access and ID tokens 300 seconds; refresh tokens a day idle and 30
days at most.

**Sender constraint**, per application: `dpop` binds access and refresh tokens to the client's key
(RFC 9449, token type `DPoP`), `mtls` binds them to its certificate (RFC 8705).

## Sessions

The cookie is `__Host-lugh_session`. A session lasts 24 hours idle and 30 days at most. It ends
at sign-out, at logout, when an administrator or its owner ends it, when its owner changes their
password (all but the one they did it through), and when they are disabled, removed or have their
factors reset. Scopes a session carries are read again every minute. Those routes are in
`docs/api.md`.

## Signing out

`/oauth2/logout` takes `id_token_hint`, `client_id`, `post_logout_redirect_uri` and `state`.

- An `id_token_hint` for this session ends it at once. An expired one is still good.
- Anything less asks the person, on a page whose answer carries the session's CSRF token.
- A hint that does not verify, or that disagrees with `client_id`, is refused on a page of Lugh's.
- `post_logout_redirect_uri` needs a hint or a `client_id` to say whose it is, and must be
  registered exactly. One that is not is refused and never followed.

**Back-channel logout** (OIDC Back-Channel Logout 1.0). When a session ends, however it ends, each
application signed in through it that registered a `backchannel_logout_uri` is posted
`logout_token=<JWT>`. The token has `typ` `logout+jwt`, lives two minutes, and carries `iss`,
`aud`, `sub`, `sid`, `iat`, `exp`, `jti` and `events`, and never a `nonce`. Verify it against the
JWKS, and answer with any 2xx.

Anything else, or no answer, is tried again after 30 seconds, then with the wait doubling, for an
hour. A redirect is not followed and does not count as delivered. The certificate and the name are
always verified. The audit log records `logout.backchannel` and `logout.backchannel.failed`.

## What is held on one node, for now

Until Lugh runs on Dagda (P8), these are in one node's memory, and a restart forgets them:

- codes, pushed requests, waiting authorisation requests and device grants;
- the revocation of an access token, so an access token stopped on one node is good at another
  until it expires;
- what stands behind an opaque access token, so a restart ends it and the client refreshes;
- back-channel logouts waiting to be delivered.

Sessions, refresh tokens, consents, applications and signing keys are in the store and survive.

## Not built

- Asking the sign-in pages for `phr` directly. An application requiring `phr`, or a request asking for it, sends a user whose
  session is below it back to sign in. A password with a WebAuthn credential, or a passkey alone, reaches it. The pages do not
  yet hide TOTP when `phr` is wanted, so a user who answers with a code is sent back again (P11, W5b).
- Dynamic client registration, front-channel logout, and the implicit and password grants: never,
  or not planned.
