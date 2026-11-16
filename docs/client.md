# lugh_client

`lugh_client` is the C++ library a relying party links to trust Lugh's tokens and to speak to a Lugh issuer: it verifies access
and ID tokens offline, keeps each issuer's signing keys fresh over HTTPS, runs the OAuth 2 and OpenID Connect flows, and calls
the management API. It knows nothing of any one consumer; Lir's Lugh plugin, for one, adapts its verifier to Lir's own.

## Linking it

The library is the `lugh_client` target, `lugh::client` to a consumer. It depends on Dannan, Boost and OpenSSL 3, and on nothing
of the node's. A project that fetches Lugh into its own build turns the node off:

```cmake
set(LUGH_BUILD_NODE OFF CACHE BOOL "" FORCE)
FetchContent_Declare(lugh GIT_REPOSITORY ... GIT_TAG <commit>)
FetchContent_MakeAvailable(lugh)
target_link_libraries(app PRIVATE lugh::client)
```

- **One Dannan.** Declared after the consumer's own Dannan, Lugh uses that `dannan::dannan` and fetches none of its own. The
  consumer's Dannan must be the minor the Lugh commit was tested on.
- **Boost.JSON.** `lugh_client` compiles Boost.JSON's definitions (`boost/json/src.hpp`) itself. A program that links it must not
  compile them again; its own Boost.JSON code resolves against the library's.

Public headers are included as `"lugh/client/<name>.h"`. Every call that waits takes a deadline, an executor and a `done`
callback, posted to that executor exactly once and never called inline. Secrets (tokens, a client secret, a PKCE verifier) are
Dannan `Secret`s.

## Verifying tokens

`Verifier` (`verifier.h`) checks tokens offline, on the calling thread, waiting on nothing:

```cpp
lugh::client::Verifier verifier({"https://lugh.site-a.example", "https://lugh.site-b.example"}, wall_clock);
auto checked = verifier.verify_access(token, "my-api");   // std::variant<AccessToken, std::string>
```

- Each site's Lugh is its own issuer, so a verifier trusts a list of issuers, each with its own keys. A token's `iss` picks the
  keys and its `kid` the key.
- An access token (RFC 9068) is good when it is a JWS with `typ` at+jwt, ES256 or EdDSA, signed by the key its kid names, from a
  trusted issuer, with `sub`, `client_id` and `jti`, inside its lifetime (`exp`, and `nbf` when present, a minute's skew either
  side), with the audience asked for among its audiences, and with a `cnf`, if it has one, that binds it to a key (`jkt`) or a
  certificate (`x5t#S256`). The caller checks the binding against the request: a DPoP proof by that key, or that certificate on
  the connection.
- An ID token (OpenID Connect Core 3.1.3.7) is good for a client when it has `typ` JWT, the client among its audiences, `azp`
  naming the client when there are several audiences or any `azp` at all, `exp` and `iat`, and the nonce the client sent.
- A refusal says why, in words a person can read. Three of them tell a key source to look again: "no keys yet for its issuer",
  "no key with its kid", and the issuer is not trusted.
- What offline verification cannot see: a revocation. A token is honoured until its `exp`; Lugh's access tokens are short-lived
  by each application's setting. Introspection is the online question.

## Keeping keys fresh

`HttpsKeySource` (`key_source.h`) fills a verifier's keys:

```cpp
lugh::client::HttpsClient https(io_context);                    // the system's roots, or a CA bundle
auto keys = lugh::client::HttpsKeySource::make(verifier, https, executor, steady_time, {});
keys->start();
```

- For each issuer it reads `<issuer>/.well-known/openid-configuration`, which must name that issuer and an https `jwks_uri`, then
  the JWKS, into the verifier.
- It fetches at start, then hourly, and when a token is refused for a kid the keys lack or an issuer with no keys, at most once a
  minute per issuer, so a stream of forged kids costs one fetch a minute.
- A failure keeps the keys already held and is tried again after a backoff of 5 seconds doubling to 5 minutes. `status()` shows
  each issuer as waiting for its first keys, fresh, or stale, with its failures and last error; `refresh_now()` fetches every
  issuer at once.
- The settings (`refresh`, `missing_gap`, `first_backoff`, `most_backoff`, `fetch_deadline`) change those times.

## HTTPS

`HttpsClient` (`https.h`) is the library's HTTPS: GET, POST, PATCH, PUT and DELETE, with headers and a body, answering the
status, type, caching, ETag and a body of at most 64 KiB. The server's certificate and name are always verified, with no way to
turn that off; a redirect is an answer, never followed. Given a certificate chain and key, it presents them when a server asks
(RFC 8705). Each request is one connection made by Dannan's `StreamConnector`. The roots (a PEM bundle, or the system's bundle
file) and the client's certificate are read once when the client is made, so a bad path is an error then, not at the first
request.

## The flows

`OAuthClient` (`oauth_client.h`) is built from an issuer's endpoints, read from its discovery document
(`Endpoints::from_discovery`), and the client's identity:

| How the client authenticates | `ClientIdentity::Method` |
|---|---|
| A public client: its `client_id` only | `none` |
| An assertion signed by its key, for the token endpoint, a minute's life, a fresh `jti` (RFC 7523) | `private_key_jwt` |
| Its id and secret in the Authorization header, each form-encoded (RFC 6749 2.3.1) | `client_secret_basic` |
| The certificate its `HttpsClient` presents, on the issuer's mTLS endpoints (RFC 8705) | `tls_client_auth` |

- **Authorisation code** (RFC 6749 4.1, RFC 7636): `authorization()` makes the browser's URL with a fresh state, nonce and PKCE
  verifier (S256), which the caller keeps; `pushed_authorization()` pushes the request first (RFC 9126) and leaves only the
  `request_uri` in the URL. `callback()` checks the browser's return for the issuer (RFC 9207), the state and any error, and
  answers the code; `redeem()` exchanges it and verifies the ID token with the nonce.
- **Refresh**: `refresh()`; Lugh rotates refresh tokens, so the answer's refresh token replaces the old one.
- **Client credentials** (RFC 6749 4.4): `client_credentials()`.
- **Device** (RFC 8628): `device_authorization()` begins it and gives the code the person types; `device_tokens()` polls every
  interval from the last answer, five seconds more after `slow_down`, until tokens, a refusal, or the code's expiry.
- **DPoP** (RFC 9449): with `ClientIdentity::dpop_key`, every token request carries a proof, so the tokens are bound to the key;
  `dpop_proof_for()` makes the proof for a resource request, sent with `Authorization: DPoP <token>`. Lugh asks for no DPoP
  nonce.
- **Certificate-bound tokens**: a client with `certificate_bound` set calls the mTLS endpoints, so its certificate binds the tokens.
- **Introspection** (RFC 7662) and **revocation** (RFC 7009): `introspect()` and `revoke()`. A public client may not introspect.

A refusal from the issuer reads `<error>: <error_description>`, its OAuth error code first.

## The management API

`ApiClient` (`api_client.h`) calls a node's `/api/v1` with an access token, as Bearer or, with a DPoP key, as DPoP with a proof per
call. A write carries the ETag last read as `If-Match` (Lugh refuses a write without one); the answer carries the status, the JSON
body and the record's ETag. The API's errors come back as Lugh's faults by their code: `not_found`; `changed` as a conflict
(another wrote first: read again); `duplicate`; `invalid` and `if_match_required`; `refused`, and a 401 or 403, as refused. The
routes are in `docs/api.md`.
