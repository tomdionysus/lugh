# Complete

What shipped, newest first, with the date and why.

## 2026-11-04: P6 step O10c, the whole flow on the real binary

- `node_process_oauth_test.cpp`: root signs in and enrols, registers an application through the API, consents, redeems the code, reads userinfo and refreshes; the sign-out reaches a real HTTPS server over a verified post, and the logout token checks out against the published keys; the old cookie and the refresh token are dead after it. The same across a restart between sign-in and sign-out. Nothing secret reaches the log.
- `docs/oauth.md` written. `docs/api.md` had stale sections (coroutines, signing in as still to come, no sessions routes); brought up to date, with `docs/architecture.md`'s LDAP row and `ACTIVE.md`.
- Found doing it: `opaque_access_tokens` is stored and shown but not honoured.
- Tests: 516 to 518, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-04: The way back to a client after a form

- `form-action 'self'` also covers where a form's answer redirects to, so a browser that enforces that would have stopped a consent answered, or a sign-in resumed, on its way back to the client. Those now leave by a page (`signin::write_leaving`) that goes on by itself and carries a link. An authorisation request that no form led to still gets a 303. Not yet tried in a real browser.
- Tests: 514 to 516, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-04: P6 step O10b, logout

- `/oauth2/logout` (OIDC RP-Initiated Logout 1.0): an `id_token_hint` of this session's ends it, expired or not; anything less asks the person, on a page whose answer carries the session's CSRF token. A `post_logout_redirect_uri` must be registered exactly by the application the hint or `client_id` names; otherwise it is refused and never followed.
- The session record keeps the applications signed in through it (format 2; format 1 still read), noted before a code or a device approval is issued, so a logout cannot miss one.
- `BackchannelLogout` (OIDC Back-Channel Logout 1.0): when a session ends, however it ends, a logout token (`typ` logout+jwt, two minutes, fresh for each try) goes to each of its applications that registered a URI. Tried again with the wait doubling from 30 seconds, for an hour; delivery and giving up are audited. What waits is in memory, so a restart forgets it.
- `lugh/http/outbound.h`: an HTTPS client that always verifies the certificate and the name, follows no redirect, and has no way to turn that off. `oauth.outbound_ca` changes the roots.
- `signin::write_leaving`: leaving Lugh from a form's answer goes by a page, not a 303, since `form-action 'self'` covers where a form's answer redirects.
- `session_sessions_test` used format 2 as its unknown format; format 2 is now real, so it uses 3. No test removed.
- Tests: 483 to 514, green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O10a, sessions managed and ended

- `Sessions`: a user's sessions listed from memory; one ended by its sid; all of a user's ended but one; and `on_end`, told of every session that ends, however it ends, which O10b's back-channel logout starts from.
- `/api/v1/me/sessions` (list, end one), `/api/v1/me/password` (current and new, through the person's own session only, never a token; every other session of theirs ends), `/api/v1/users/{id}/sessions` (list under directory.read, end all under a new scope, `lugh:sessions.write`).
- A user disabled, removed or with their factors reset loses every session at once, not at the next minute's refresh; a refresh family dies with its session, so the applications' next refresh fails.
- Tests: 479 to 483, green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O9, the device grant

- `lugh/oauth/device_grants.h` (RFC 8628): a device's request answered with a device code and a user code, eight letters from twenty consonants drawn by rejection so each is as likely, shown `XXXX-XXXX` and taken any case with or without the dash. Held in memory on the node for ten minutes; approved or denied once; the approval answered to the device's poll once. Polling sooner than the interval is `slow_down`, and the interval grows by five seconds.
- `/oauth2/device`, and the token endpoint's device_code grant with its errors (authorization_pending, slow_down, access_denied, expired_token), with a refresh token where the application has that grant.
- `/signin/device`: the code typed or carried in from `verification_uri_complete`; a user not signed in goes through the sign-in pages and back with the code; the approval page names the application and what it asks for; approval only for the application's groups and at its least `acr`.
- Tests: 475 to 479 (user codes, polling and slow_down, denial and expiry, and the whole flow from the TV's request to its tokens), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O8b, mTLS

- `TlsContext` gains a client-certificate mode: asked for, never required, never ending a handshake; the chain's check against `tls.client_ca`, when set, kept for the routes. `HttpServer` reads the certificate after the handshake on the mTLS listener and hands its thumbprint (x5t#S256), subject (RFC 2253) and whether it chained to the CA to the routes in `Lugh-Client-Cert-*` headers (`lugh/http/client_certificate.h`), which it removes from every request it reads, on every listener, before it sets its own.
- `tls_client_auth` (RFC 8705 section 2): a client named by its certificate's thumbprint, or by its subject when it chains to the client CA.
- Certificate-bound tokens (RFC 8705 section 3): an application whose `sender_constraint` is mtls gets access tokens with `cnf.x5t#S256`, accepted only on a connection presenting that certificate. The issuer's binding is now a `cnf` object, a DPoP key or a certificate.
- The node runs the mTLS listener when `oauth.mtls_port` is set, with every route but the sign-in pages and the dashboard; the metadata names its endpoints in `mtls_endpoint_aliases` and offers `tls_client_auth` only then.
- Departure, for the maintainer: a second listener rather than the main one asking for certificates (TODO/2026-11-04-oauth.md, O8).
- Tests: 470 to 475 (the listener handing on a certificate, verified against a CA or not; a client's own claim dropped on both listeners; tls_client_auth by thumbprint and by subject; certificate-bound tokens at the API; the metadata's aliases; the settings), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O8b, DPoP

- `lugh/oauth/dpop.h` (RFC 9449): a proof's own parser, since Lugh's JWS parser refuses a key in the header and a proof is exactly that: typ dpop+jwt, alg ES256 or EdDSA, a public jwk, nothing else; checked for its method and URL, made within five minutes either way, used once on the node, and for an access token carrying its hash. RFC 7638 thumbprints, matching RFC 9449's own example.
- The token endpoint binds what it issues to a proof's key: `cnf.jkt` in the access token, `token_type` DPoP, and the key's thumbprint in a new refresh family (the family's record gains it; format 1 is still read). An application whose `sender_constraint` is dpop gets nothing without a proof.
- A bound token is accepted only with the DPoP scheme and a proof by its key, for that request and token, at the API and at userinfo; presented as a bearer token it is nothing.
- Found by the tests and fixed: a bound family's key was checked after the rotation, so a refresh refused for want of a proof left the client's token stale and its next try read as reuse. The key is now checked first, and a refused refresh changes nothing.
- Tests: 464 to 470 (the thumbprint vector, proofs and their refusals, the checker's rules, binding through the token endpoint and the API, a bound family), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O8a, refresh tokens, revocation and introspection

- `lugh/oauth/refresh_tokens.h`: refresh tokens as the maintainer decided, replicated with the session and single use by the family's version. A token is `rt.<family>.<secret>`; the family, in the sealed `grants` table, keeps only the hash of the newest secret. Rotation writes the family at the version it read; a token that is not the newest, or the loser of two rotations racing, is reuse, and revokes the family (RFC 9700 section 4.14.2). A family ends with its Lugh session (`Sessions::live_sid`), at the application's idle and absolute lifetimes, and when revoked. A refresh may narrow the scopes, never widen them, and makes no new ID token.
- The token endpoint takes `refresh_token`, and a code exchange gives one to an application with that grant.
- `/oauth2/revoke` (RFC 7009): the client's own refresh token's family, or its access token, refused by jti until it expires (held in memory on the node; every node holds its own until P8). Always 200.
- `/oauth2/introspect` (RFC 7662): for the client that holds a token, or an api among an access token's audiences; never for a public client.
- Tests: 458 to 464 (rotation and reuse, narrowing, the session's end, the idle lifetime, revocation, introspection), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O7, the authorisation code flow

- `lugh/oauth/request.h`: the authorisation request checked as RFC 6749, RFC 7636 and OIDC Core have it, with Lugh's profile: response_type code only, the redirect URI exactly as registered (any port on a native app's loopback URI, RFC 8252), PKCE S256 required, state required, a nonce with openid, prompt none, login or consent, max_age and acr_values. A request whose client or redirect URI cannot be trusted is refused on a page of Lugh's; every other refusal goes back with state and iss (RFC 9207). The scope cut: what was asked, of what the subject holds, for the token's audiences.
- `lugh/oauth/flow_routes.h`: `/oauth2/authorize`, the resume after sign-in, consent, PAR (RFC 9126), the token endpoint (authorization_code with PKCE, client_credentials) and userinfo. A request without a session good enough for it (none, too weak an acr, prompt=login, past max_age) goes through the sign-in pages, which now carry it and return to it. Only the application's groups' members get a code; a third party asks consent once (`consents`, a new component). Codes, PAR URIs and waiting requests are in memory on their node and used once (`lugh/oauth/expiring.h`).
- `lugh/oauth/client_auth.h`: client_secret_basic, private_key_jwt (a key from the client's JWK Set, iss and sub its client_id, aud this server, a jti never seen, at most ten minutes) and none. tls_client_auth waits for O8's client certificates.
- `lugh/oauth/issuer.h`: access tokens (RFC 9068, at+jwt) and ID tokens (OIDC Core, with at_hash, the claims profile, email and groups allow, and the application's roles); userinfo's claims; and verifying an access token from memory. A bearer token with `lugh` in its audiences is an API caller (`Caller::Kind::service` for a client's own).
- Lugh's encoding gains a strict standard base64 decoder, for HTTP Basic.
- Departures for the maintainer are in TODO/2026-11-04-oauth.md, O7.
- Tests: 443 to 458 (the request's rules with RFC 7636's vector, the whole code flow from no session to userinfo and the API, a code bound to its client, redirect and verifier, refusals at the authorisation endpoint, access groups, consent, client credentials, private_key_jwt, PAR), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O6 (LDAP's L2), app passwords

- `lugh/authn/app_passwords.h`: app passwords in the sealed `app_passwords` table, keyed `<user>/<instance>`. 160 random bits as 32 base32 characters, shown once in lower-case groups of four, typed any case with or without dashes; the first four characters select the record, so a guess costs one Argon2id hash, and a miss costs the same. Each carries a name, a scope set (`lugh:directory.read` unless its creator says otherwise, the maintainer), and optionally the networks it may be used from; it is revoked alone, stops working when its user is disabled, and goes with its user. At most 32 per user. Every change audited.
- The routes: an administrator's for any user under `lugh:credentials.write`, and the caller's own under `/api/v1/me/app-passwords`, never with a scope the caller does not hold.
- Not yet: using one. The LDAP bind (L4) checks it with the sign-in's back-off and cuts its scopes to what its owner's groups grant at that moment.
- Tests: 435 to 443, green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O5, sessions and the sign-in pages

- `lugh/session/`: the Lugh session (`Sessions`), in the sealed `sessions` table keyed by the SHA-256 of a 256-bit handle, held in memory so a request resolves without waiting; 24 hours idle, 30 days at most (the maintainer); a CSRF token per session; ended by signing out, by expiry, and when its user is disabled or removed. `refresh()`, run by the node every minute, reads each session's user and scopes again and saves when it was last seen. The sign-in in progress (`PreSessions`) is in memory on its node, under a visitor cookie that every form's CSRF token is made from with a per-process key; nothing is held for a visitor until a password is accepted, and past 10,000 the oldest is dropped.
- `SessionCallers`: the API's first callers. A session's cookie, and on any request but GET and HEAD its CSRF token in `X-CSRF-Token`.
- `lugh/signin/`: the server-rendered pages, no JavaScript, under `default-src 'none'; style-src 'self'; form-action 'self'`, every value escaped: the password; the second factor, a TOTP or a recovery code; a new password from an enrolment link; enrolling a TOTP factor, a wrong code keeping the same secret and the wrong-code count; the recovery codes shown once; signed in; signing out. Root's first sign-in goes from genesis's password to enrolment. The stylesheet is in the dashboard's tokens.
- `lugh/http/forms.h`: form bodies (Dannan's form decoding; a name given twice refused), cookies (a cookie given twice taken as none), and `__Host-` Set-Cookie values. The server keeps a response's own, tighter CSP. The router gains `add_authenticated()` for `/api/v1/me`, and refuses a protected route without a scope.
- `GET /api/v1/me`: the caller, its scopes, and its session's CSRF token.
- `fuzz_form`, over form bodies and cookies; syntax-checked only here.
- Departures from the plan, for the maintainer: scopes read again within a minute rather than at once, and CSRF required only where something may change (TODO/2026-11-04-oauth.md, O5). Not yet: the TOTP QR code (O5b).
- Tests: 413 to 435 (forms and cookies, sessions and their lifetimes, refresh following the directory, the sign-in in progress, every page's flow and refusal, root's first sign-in, the API through a session, and the real node from genesis's password to an API change through the session), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O4, signing keys, JWKS and metadata

- `lugh/tokens/jose.h`: a public key as a JWK (P-256 and Ed25519, built and read as the SubjectPublicKeyInfo Dannan signs with), and a compact JWS signed and verified with Dannan's ES256 and EdDSA. Parsing refuses every algorithm but those two (no `none`, HMAC or RSA), a missing kid, and any header member but `alg`, `kid` and `typ` (no `crit`, `jku`, `jwk`); verifying takes the algorithm from the key, never from the token. RFC 7515 A.3 and RFC 8037 A.4's signatures verify.
- `lugh/core/encoding.h`: a strict base64url decoder, one spelling per value.
- `SigningKeys`: the sealed `signing_keys` table, held in memory so signing and publishing never wait. A key of each algorithm is made at a cluster's first start; a rotated key is published an hour before it signs, and the key it replaces stays published two hours after that, longer than any token lives; nothing is deleted. An hourly check in the node rotates a key that has signed for 90 days. Every key made or rotated is audited.
- `/oauth2/jwks` (open, cached five minutes), and the server metadata at `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` when `oauth.issuer` is set (a new setting, `--issuer`, `LUGH_ISSUER`; https, no query, fragment or trailing '/'). The metadata names every endpoint of the profile, which the coming steps serve.
- `/api/v1/keys` and `/api/v1/keys/rotate`, and a new scope, `lugh:keys.write`.
- `fuzz_jws`, over JWS parsing and verification and JWK round trips; syntax-checked only here.
- Tests: 392 to 413 (base64url, JOSE with the RFC vectors and the refusals, the keys' life, the metadata, the key routes, the issuer setting, and the real node serving the same JWKS across a restart), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O3, applications

- `lugh/apps/`: an application's record and every rule that can be checked without the store (`validate()`): client authentication by kind, a JWK Set of public keys only, redirect URIs written exactly (https, no fragment or user information, loopback http for native apps only), grants by kind, prefixes, audiences, role names, the least `acr`, and lifetimes.
- `Apps`: register (a random `client_id`, a secret shown once where `client_secret_basic` is allowed), read, list, replace (keeping what never changes), the groups that may sign in, role mapping, secret rotation with a 24-hour overlap, removal as a tombstone so a `client_id` or prefix is never reused. Scopes and audiences must belong to a registered api; the scope grants check that too now. Every change audited.
- One record per application, holding its access groups and role mapping, so each change is one versioned write; the `app_access` table is unused. Client secrets are in that record as Argon2id hashes; on Dagda (P8) they move to `lugh/secrets` with the other credentials.
- The API: `/api/v1/apps` and its access, roles and secret routes (`docs/api.md`, "Applications"); a new scope, `lugh:apps.write`, which genesis gives administrators with the rest; and the setting `oauth.allow_client_secrets`, off by default.
- The records fuzz target reads applications and scope grants too.
- Tests: 369 to 392 (the record's rules, the component, the routes, and the grant check), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: onto Dannan 0.4.0's settings reader and percent-encoding (rule 3)

- **Dannan pinned to its tag 0.4.0.**
- **Percent-encoding:** the router decodes with Dannan's (`dannan/encoding/percent.h`). Path parameters are decoded strictly (`+` stays `+`, as RFC 3986 has it for paths) and queries as forms (`+` a space); a malformed escape (`%zz`, a trailing `%`) is answered 400 instead of passing through as it did. `Router::percent_decode` is gone; its unit test became a test through a route of both modes and the 400.
- **Settings:** `ConfigLoader` reads through Dannan's reader (`dannan/config/config.h`), which was lifted from it. Lugh declares its settings (`ConfigLoader::settings()`) and keeps its typed `Config` and its own checks: addresses, networks, log levels, the TLS pair needed to serve, the command word, `--passphrase` only for init. The command line keeps only `--help`, `--version` and `--passphrase`; everything else, the command word among it, goes to the reader, and the command is now `Config::command`. Lugh no longer uses yaml-cpp itself (Dannan still does).
- **The environment port** was an exact copy of Dannan's: `lugh::system::Environment` is now `dannan::config::Environment`, `SystemEnvironment` is deleted, and the composition root hands out `dannan::config::process_environment()`, which the IoC check now allows nowhere else.
- `fuzz_cli` is deleted: what it fuzzed, the command line, is parsed by Dannan's reader now, and Dannan fuzzes its own parsers.
- **Tests: 378 to 369.** A drop, so here is why. The CLI tests went from 11 to 3: what they covered (both flag forms, every setting's flag, unknown and valueless flags) is Dannan's reader's, tested in Dannan; the command word, stray words and `--passphrase` moved into the config tests. The config tests went from 19 to 18: the three layer-order tests became one (`TheLayersInOrder`), `TheStateDirectory` and `TheBreachedPasswordList` were folded into the defaults and file tests, and three were added (the command word, `--passphrase` only for init, unknown and valueless flags); the bad-values test also checks a bad log format now. Green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O2, the scope model

- `lugh/scopes/`: what a scope is (RFC 6749 section 3.3's word, at most 1024 bytes) and its four kinds, Lugh's own, OIDC's, an application's `<prefix>:<name>` and Lir's topic scopes; the space-delimited list split and joined. Lugh's own scope names move here from `lugh/api/scopes.h`, which now refers to them.
- Lir's topic-scope grammar as the maintainer decided it (`lir:pub|sub|retain:<filter>`, `{sub}` the one substitution, a whole level), decoded strictly and encoded with Dannan's percent-encoding (Dannan pinned to 32f163b for it). A grant whose filter is not a valid MQTT filter is refused, and an encoded scope decodes to what was encoded.
- `scope_grants` (a new table): which scopes each group grants, versioned for ETags; a user's effective scopes are the union over their groups, read when needed. Genesis grants `administrators` every Lugh scope.
- The API: `GET /api/v1/scopes`, and `GET`/`PUT /api/v1/groups/{id}/scopes` (`lugh:policies.write` to change, with `If-Match`).
- `fuzz_scope`, a libFuzzer target over the list, the kinds and the topic grammar's round trip. Syntax-checked only: this machine has no clang with libFuzzer.
- Not in O2, and why: an application's prefix is checked against the registered apps in O3; `ScopeSource` over an in-memory image of the grants is P8's, since nothing installs it before Lugh runs on Dannan's Context.
- Tests: 356 to 378 (the scope rules, the topic grammar, the grants, the routes, genesis's grant), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O1, the name parts and the POSIX number

- `User` gains `given_name` and `family_name` (optional, printable, at most 128 bytes) for OIDC's `profile` claims and LDAP's `givenName` and `sn`, and `posix_number`; `Group` gains `posix_number`. Nothing allocates a number yet; LDAP's L-steps do (`TODO/2026-11-04-ldap.md`).
- The user and group records move to format 2. Format 1, which the frozen store holds, is still read, as having no name parts and no number, and never written.
- The API takes and shows `given_name` and `family_name` on create and `PATCH`, and shows `posix_number` once there is one (`docs/api.md`).
- Tests: 353 to 356 (the new record format, format 1 still read, the POSIX flag checked; the directory's name parts; the API's), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-03: Aligning with Dannan and Dagda (feature/dannan-alignment, in progress)

The maintainer, 2026-11-03: Lugh uses Dannan as its network and Dagda as its datastore, no code is
duplicated between the three, and all three share one style, set of conventions and
layout. Kept until Dagda carries Lugh's spaces: the sealed store and keyring ("Keep the
store until Dagda"). The stack and its seams are in `../dagda/TODO/2026-11-03-stack.md`.

- The GPLv3 header block ("Lugh - The Directory") and `LICENSE`; Dannan linked, pinned to a
  commit of `feature/wire-v1` until a tag carries its Context; MacPorts for every dependency.
- Dannan's layout: `lugh/<subsystem>/`, `lugh/test/` flat, `lugh/fuzz/`, `tools/` (the service
  is `lugh-node`), `test/process/`, `TODO/COMPLETED.md`.
- From Dannan in place of Lugh's own: SHA-256, the constant-time compare and hex
  (`dannan/identity/crypto.h`), Argon2id and its ceiling on stored costs
  (`dannan/identity/argon2.h`, `Argon2Costs::valid()`), and signing
  (`dannan/identity/signing.h`; Lugh's copy deleted, it had no user yet).
- Finding: the unit count went from 389 to 373. The tests that went were of what Lugh no
  longer owns: its SHA-256, compare and signing copies, and the RFC 9106 Argon2id vectors,
  all tested in Dannan against the same published vectors.
- The wall clock and the steady time source are Dannan's (`dannan/contract/`), and the tests
  step Dannan's `SteppedTime` and `SteppedWall`.
- Secure memory, the record codec, HKDF and AES-256-GCM are Dannan's: `SecureBuffer` on
  Dannan's locked pages, every record and file format written with Dannan's `Writer` and
  read with its `Reader` (`lugh/core/codec.h` holds only `SecureWriter` and
  `decode_whole`), the keyring's KEK from `hkdf_sha256_secret`, and `crypto/aead` reduced to
  the sealed-value framing (nonce, ciphertext, tag) over `aes_gcm_seal` and
  `aes_gcm_open_secure`. The keyring and table log formats keep their bytes. The node
  hardens itself with `harden_process()`. Lugh's `core/byte_io.h`, `core/secure_memory`
  and `crypto/hkdf` are deleted.
- Finding: the unit count went from 373 to 353, all of it what Lugh no longer owns: its
  byte codec, secure memory and HKDF tests, the GCM known-answer vectors and the Argon2
  ceiling (each tested in Dannan), and the test that a broken random source seals nothing,
  since Dannan draws the nonce itself and Lugh cannot inject that failure any more.
- The warning that key material could not be locked into memory reads Dannan's
  process-wide count, `unlocked_secure_allocations()`, added at Lugh's request (Dannan
  6d173c1, which Lugh is now pinned to); the node also warns when `harden_process()` falls
  short.
- `Secret` is Dannan's: move-only, on locked pages, compared in constant time with `==`.
  `lugh/core/secret.h` keeps only the redaction text and the text on either side of a
  secret (`text_secret`, which wipes the string it is given, and `secret_text`). A secret
  read a character at a time is built in a `SecureBuffer` and handed over. Where a caller
  still needs a secret it passes on, the copy is written out at the call site.
- Finding: the unit count went from 353 to 351: the copy and growth tests of Lugh's
  `Secret`, which no longer exist to test.
- Randomness is Dannan's: `random_bytes` for what is not secret (ids, salts) and
  `Secret::random` for what is, through `secure_random()` in `lugh/core/secure_bytes.h`
  when it must land in a `SecureBuffer`. The `Random` port, `SystemRandom` and the test
  doubles `FixedRandom` and `CountingRandom` are deleted, as is the `random` argument of
  every constructor and of `hash_password`, `make_file_header` and `Keyring::rotate`. A
  failed generator throws: a route that meets one answers 500, and a start or `init` that
  meets one stops.
- Finding: the unit count went from 351 to 347. The four tests that went made the random
  source fail and saw a user, a factor, root's password or a keyring refused; with Dannan
  drawing the bytes, a test cannot make it fail. The tests that relied on two rigs drawing
  different bytes now draw from the real generator.
- Logging is Dannan's (`dannan/status/log.h`): the node has one `LogSink`, made in
  `tools/lugh_node.cpp` by `console_sink(format, level)` (text, or JSON lines through
  Dannan's `JsonSink`, added at Lugh's request), and each component takes the sink and
  scopes its own `ScopedLogger` ("store", "audit", "authn" and so on), as a Dannan component
  takes `Context::logger(scope)`. `log.level` and `log.format` are read with Dannan's
  `parse_log_level` and `parse_log_format`, so `all` is now a level. The tests record
  through `RecordingSink`. Lugh's `loggers/` (from blackraven-admin) is deleted, and the IoC
  check refuses a concrete sink outside the composition root. Dannan is pinned to ca8a565.
- Finding: the unit count went from 347 to 338: the tests of `LoggerScoped` and
  `LoggerStdIO`, whose behaviour is now Dannan's and tested there.
- Every lock is Dannan's (`dannan/contract/thread_safety.h`): `Mutex` under `Lock`, the
  state it guards `DANNAN_GUARDED_BY` it and a helper called with it held
  `DANNAN_REQUIRES` it, in the library and the test fixtures alike, so clang's analysis
  (`-Werror=thread-safety`) checks every access. A table's state lock in the sealed store
  is an `IoMutex`, since a record that does not open is logged with it held. Opening a
  table and loading its keys now take that lock around the state they touch, though
  nothing else can see the table yet, so the analysis can prove every access. The IoC
  check refuses a standard lock outside the composition root.
- The tests write only inside the build tree, as Dannan's do: `TempDirectory` is Dannan's
  `TempDir` (under `build/test-tmp`) with a `write()` helper, and ctest gives the process
  tests `TMPDIR` there. Before, both used the system temp directory.
- HMAC-SHA-256 is Dannan's, and Lugh had no caller of its own copy; HMAC-SHA-1, which only
  TOTP uses, moved into `authn/totp.cpp`. `crypto/hmac` is deleted. Finding: the unit count
  went from 338 to 335, the HMAC known-answer tests; HMAC-SHA-1 is still checked through
  RFC 4226's and RFC 6238's vectors.
- `CONTRIBUTING.md` from Dannan's, section for section, with Lugh's own rules on secrets
  and inversion of control beside them, and a local `CLAUDE.md` (gitignored, as Dannan's
  is) from Dannan's. `docs/code-style.md` is gone: its rules are in `CONTRIBUTING.md`, and
  its tables of what was lifted from where are `docs/provenance.md`. Following the rule
  The maintainer set for all the source repositories, sanitizers now run before a release rather
  than routinely, which `code-style.md` had made a deliberate Lugh exception.
- Dannan's warning set on every target: `-Wshadow -Wconversion -Wno-sign-conversion` beside
  `-Wall -Wextra -Wpedantic`, under `-Werror`. The library and the node were already
  clean; three tests were not (a shadowed name twice, a narrowing in a loop).
- `SystemFiles::write` is Dannan's `durable_replace_file`, or `durable_create_file` when an
  existing file must not be replaced (added at Lugh's request; it ends in `link()`, so of
  two inits racing exactly one makes the keyring, and Dannan's own key custody had the
  same race, now closed). Lugh's temporary, sync, rename and link code is deleted. Dannan
  is pinned to bd2f720. Finding: a write now makes the directories its file needs, where
  Lugh's refused; the test says so. At Lugh's request Dannan makes them 0700, one level at
  a time, as Lugh's own did (Dannan 7f02e58, Lugh's pin), and the test checks it.
- The rules follow the maintainer's decisions of 2026-11-04: Lugh keeps its presets (the `fuzz`
  preset's option is fixed: `LUGH_BUILD_FUZZING`, not the old `LUGH_FUZZ`) and runs the
  sanitizers routinely, its two exceptions to the stack. The stale `build-asan` and
  `build-tsan` trees from the old layout were deleted and built afresh. Under ASan and UBSan
  and under TSan, `lugh_tests` (335) and `ctest` (5) pass. Finding: ASan stopped the test
  binary as GoogleTest registered its tests, with a false container overflow where
  MacPorts' uninstrumented GoogleTest meets libc++'s annotated containers; the ASan test
  binary now turns container-overflow detection off (`lugh/test/sanitizer_options.cpp`),
  every other check on.
- Dannan is pinned to its first release tag, 0.2.0 (`LUGH_DANNAN_TAG`), in place of a
  commit, and linked as `dannan::dannan`, the name an installed Dannan exports. Under the
  debug build, ASan with UBSan, and TSan, `lugh_tests` (335) and `ctest` (5) pass.
- No Python (the maintainer, 2026-11-04), first part: the IoC check is a GoogleTest test,
  `lugh/test/node_ioc_check_test.cpp`, in `lugh_tests`, and `tools/lugh_ioc_check.py` and
  its ctest entry are gone. The same patterns and adapters; the one lookbehind is written
  without one, as `std::regex` has none. Each pattern now proves it catches an example of
  what it forbids, and that some of Lugh's own calls (`_time.now()`, `boost::asio::write`,
  Dannan's `Lock`) are not caught; a `getenv` planted in a library file was named and failed
  it. A plain-text prefilter keeps the scan near 0.2 s in a debug build. Unit count 335 to
  339; `ctest` 5 to 4.
- No Python, second part: the shutdown, `init` and API process tests are GoogleTest tests in
  `lugh_tests` (`node_process_shutdown_test.cpp`, `node_process_init_test.cpp`,
  `node_process_api_test.cpp`), check for check what the Python ones did, over a fixture
  (`lugh/test/fixtures/node_process.h`) on Dannan's `ChildProcess`. Dannan gave
  `ChildProcess` an environment, standard input, a pseudo-terminal, raw reads and any signal
  for them (ca029bb, Lugh's pin until the next tag; the pin is now `LUGH_DANNAN_REF`, a tag
  or a commit). The certificate is made in-process rather than by the `openssl` command,
  and every request and wait has a deadline. `test/process/` and the ctest entries are gone;
  `ctest` runs `lugh_tests` alone. Seven tests where there were three scripts: 339 to 346,
  passing in the debug, ASan and TSan builds.
- Callback style, first piece: `lugh/core/completion.h`, the one place that keeps Dannan's
  promise for an operation's answer (posted to the caller's executor exactly once, the
  answer or the deadline's, never inline), with five tests, run twenty times under TSan
  with no report. `Executor` moved there from `core/task.h`. The design for the rest is in
  `TODO/ACTIVE.md`. 346 to 351.
- Callback style, the audit log: `open`, `record`, `entries` and `verify` take Dannan's
  shape. The async lock held across numbering and writing is now a queue on the log, one
  write in flight, each entry numbered only once the one before has settled, so the chain
  keeps no gaps and no forks; a caller past its deadline is told the entry may yet be
  recorded, and it keeps its turn. `entries` answers `failed` on a store failure or the
  deadline rather than a short page. The frozen store is reached through
  `lugh/store/store_calls.h`; the layers not yet converted reach the log through the
  temporary bridge `lugh/core/awaited.h`; the tests through `wait_for` and
  `lugh/test/fixtures/audit_calls.h`. A new test has 100 callers on four threads record at
  once: one intact chain of 100, no TSan report in five runs. 351 to 352.
- Callback style, the directory: all twenty operations take Dannan's shape, each one
  `Completion` over steps that each start the next (names checked free, the record put,
  the change audited, memberships tidied in turn). A read answers `Outcome`, `failed` and
  never "absent" when the store fails or the deadline passes; a coroutine caller in
  transition gets the value through `awaited_value`, which throws for a read that could
  not happen (the router answers 500), and the dependents' `forget` (still coroutines) is
  run through `spawned`. The 77 calls from the routes, authn, the node and the tests were
  rewritten by rule, not by hand: the operation's answer type from a table, a deadline
  added, and `std::nullopt` where `expected` had been left to its default. A new test reads
  and writes through a store slower than the deadline: the read is `failed`, the write says
  it may yet be made. 352 to 353, in the debug, ASan and TSan builds.
- Callback style, the policies and the passwords. The step helpers (`answering`, `refusing`,
  `in_turn`, and `on_pool` for blocking work) are `lugh/core/steps.h`. Argon2id runs on the
  hashing pool through `on_pool`, the password held in a `shared_ptr` where a step needs it,
  since a `Secret` is not copied; `verify` and `has_password` answer `failed` rather than
  a false "no" when the store fails or the deadline passes. The directory's `Dependent`
  takes the callback shape; factors, not yet converted, answers it by running its
  coroutine through `spawned`. 353, in the debug, ASan and TSan builds.
- Callback style, the enrolment links: all seven operations. A token is a `Secret`, held in
  a `shared_ptr` between steps and moved out at the end. "No such link" stays an ordinary
  refusal (the callers act on it), so `peek`, `link` and `spend` keep their `Outcome` through
  the bridge; only a store failure or a passed deadline is `failed`. 353, in the debug, ASan
  and TSan builds.
- Callback style, the factors: all nine operations, TOTP and recovery codes, with the codes'
  Argon2id on the hashing pool. The temporary wrapper that let `forget` run as a coroutine
  is gone. A wrong code, a replay and a lost race stay `refused`; a failed store or a passed
  deadline is `failed`, never a wrong code. 353, in the debug, ASan and TSan builds.
- Callback style, genesis: one chain of steps (no one there yet, root, administrators, the
  membership, the password, the first sign-in, the audit entry), each holding copies of
  what it needs, so the `Genesis` built for the call may go at once. 353.
- Callback style, the authenticator: every sign-in step, enrolment, removing a factor and
  the reset. The rules are as they were (back-off before any hashing; the same work for a
  known and an unknown name; the link spent only after the password is accepted; every
  refusal audited), the steps now one chain each. One change of behaviour: a read that
  could not happen part way through a sign-in used to throw out of the coroutine; it is now
  answered `Step::Kind::failed`, the kind that was always meant for it. Every authn
  component and the directory and audit log are now callback style; the routes, router
  and node still reach them through the bridge. 353, in the debug, ASan and TSan builds.
- Callback style, the router and every route. A handler is a plain function, run on the
  router's executor with that executor in its context; a request is in flight until it is
  answered, once, and one that throws while starting is answered 500 as before. The routes
  call the directory, authn and the audit log directly, one chain each, with a deadline
  each (`kRouteDeadline`), and answer a failed read as a 500 rather than by throwing. The
  500 now says "the request could not be completed", not "nothing was changed": past a
  deadline a change may yet land. The API fuzz target's handler follows (syntax-checked
  with the library's flags; no libFuzzer here to build it). 353, in the debug, ASan and TSan
  builds.
- The callback change is done above the frozen layers. The node's start-up stays a
  coroutine sequence: it runs the frozen keyring, store and files in turn, and converting it
  now would only trade one bridge for another; it and the bridge go with them.

## 2026-10-18: P5, the management API (not committed)

- **`/api/v1`** (`src/api/`, [docs/api.md](../docs/api.md)): users (list, find by name or address, create, read, change, disable, remove), their groups and factors, removing a factor, resetting them all, enrolment links; groups and their members; the global and per-group assurance levels; the audit log a page at a time, and a walk of its whole chain.
- **Scoped permissions**: `lugh:directory.read`, `lugh:directory.write`, `lugh:credentials.write`, `lugh:policies.write`, `lugh:audit.read`. Every route declares its scope in the router, after blackraven-admin's role-checked routes: `401` with `WWW-Authenticate` for no credential, `403` for a missing scope, and callers limited per caller once known and per address until then.
- **ETags**: a user or group carries its version as a strong ETag; `PATCH` and `DELETE` need `If-Match` (`428` without, `412` stale, `*` to skip). Policies and memberships are idempotent `PUT`s and `DELETE`s, with no version.
- **Errors**: one shape, a `Fault` mapped to one status each, and unknown or mistyped body fields refused, never ignored.
- **Genesis** (`authn/genesis`), replacing a bootstrap credential at the maintainer's word: there are no static credentials, tokens, keys or settings. `lugh init` on a cluster's first node makes `root`, in `administrators`, with a random 144-bit password shown once on standard error and kept only as its hash; it is the one credential a cluster is born with. Root's first sign-in goes from that password to enrolment, once (`EnrolmentLinks::first_sign_in_*`); then root signs in as anyone does. Genesis refuses a directory with anyone in it. A person no longer needs an email address (root has none).
- **Async all the way down** (the maintainer: "it should all be async"; a first pass that put blocking work on a pool behind the routes was not enough). Every operation that waits is a C++20 coroutine on Boost.Asio (`Task<T>`, `core/task.h`): the `Store` interface and `SealedStore`, the `Files` and `Console` ports, the keyring manager, the audit log, the directory, passwords, factors, policies, enrolment links, genesis, the authenticator and every route handler. `SystemFiles` and `SystemConsole` run their system calls on a `blocking` pool, and Argon2id runs on a `hashing` pool of two threads, both through `offload()`; the caller is suspended and holds no thread. The store holds each table's writes in order with an `AsyncMutex` (`core/async_mutex.h`) across the synced append, and its state with a `std::mutex` only for moments; readers never wait on the disk, and a write is invisible until it is durable. The router spawns each handler as a coroutine, with at most 256 in flight (`503 busy` past that), and answers a handler that throws `500`, once. Startup and `lugh init` are coroutines on the io_context. The `WorkPool` lifted earlier in P5 is gone. Sign-in steps take the `SignIn` by value and hand back the next, recovery codes travel as `Secret`, and a value written to the store is `SecureBytes`. Asio's `awaitable` is `[[nodiscard]]`, so a forgotten `co_await` is a compile error; it caught two in the tests.
- **Until P6 nothing opens the API**: no caller resolves, and every route answers 401. The routes are tested through a fixed-caller fake (`tests/fakes/fixed_callers.h`).
- **Tests**: 389 unit tests, among them a store whose append is held open (and which fails if the table's write lock is taken away), showing a read of that table and a write to another finish meanwhile, the held write invisible until it lands, and a second writer queued behind it without a thread; concurrent writers through a router on a real thread pool (64 creations at once; 32 racing for one name, one winning; 16 racing adds making one membership); the router spawning handlers rather than answering inline, refusing at its in-flight limit, and answering a throwing handler once; `offload` and `AsyncMutex` themselves; every route over the API rig, the router's scope, 401, 403 and per-caller limits, and genesis with root's first sign-in; the `init` ctest now checks genesis shows root's password once, on standard error only and nowhere on disk; a new `api` ctest runs the real binary after genesis and finds the API closed to every credential presented, root's password included. A new fuzz target over the route table, query, percent-encoding, `If-Match` and body checks (`fuzz/api_request_fuzz.cpp`), run here under ASan with a stand-in driver: 300,005 inputs, no crash. All green under `debug`, `release`, `asan` and `tsan`.

## 2026-10-18: P4, directory and authentication (not committed)

- **Directory** (`src/directory/`): users (person or service; enrolled; disabled), groups and memberships over the store, with names and addresses checked and folded to lower case and unique through the store's indexes, display names checked as printable UTF-8, and every write made against the version read, so the API's ETags have something to check. Removing a user removes their memberships and, through `Dependent`, their password and factors; the name is then free for someone new under a new ID.
- **Audit** (`src/audit/`): the `audit` table, one hash-chained record per entry, with `verify()` naming the first entry missing, altered or out of order. Every change the directory and authn make is recorded, with who made it and from where.
- **Passwords** (`authn/passwords`): Argon2id hashes in `credentials`, with their costs stored so a hash under old costs is made again at the next sign-in. At least 12 characters, at most 256 bytes, not the user's own name or address, and not on the local breached list (`authn.breached_passwords`, held as SHA-256 hashes, case folded). An unknown user costs the same hash as a known one.
- **Second factors** (`authn/factors`, `authn/totp`): TOTP (RFC 6238: SHA-1, six digits, 30 seconds, one step either way), confirmed by a code before it counts, with the last step stored so a code works once, even with two sign-ins racing; ten recovery codes of 80 bits, Argon2id-hashed, with a four-character selector so a guess costs one hash.
- **Policy** (`authn/policy`): `pwd`, `mfa`, `phr`, global and per group, the strictest winning, `mfa` by default (open question 9).
- **Enrolment** (`authn/enrolment_links`): one-time links in `grants`, stored as the SHA-256 of the token, 72 hours, spent by a conditional removal so they work once, and a new link ending the old.
- **Sign-in** (`authn/authenticator`): the password, then a TOTP or recovery code; or a link, a new password, and a TOTP factor enrolled, which ends with the recovery codes. Enrolment starts only from a link, never from a password alone. Refusals all look the same. Five wrong codes end a sign-in, a sign-in lasts 15 minutes, and failures back off per account and per address (`authn/backoff.h`), answered before any hashing. The last factor cannot be removed while policy needs one, and an administrator's reset means enrolling again from a new link.
- **Also**: `crypto/hmac` (HMAC-SHA-1 for TOTP, HMAC-SHA-256), `core/encoding.h` (hex, base32, base64url), `core/outcome.h` (results with a fault the API will map to a status), `field()` in `ByteWriter`/`ByteReader`. `main` opens the audit log and builds the directory and authn after the store; nothing reaches them over HTTP until P5 and P6.
- **Deferred**: `WorkPool` moves to P6, with the first route that hashes a password. Session revocation, re-authentication before a factor change, and telling the user about one need sessions (P6).
- **Tests**: 345 unit tests, among them the RFC vectors for HMAC (2202, 4231), HOTP and TOTP (4226, 6238) and base32/base64url (4648), and the whole sign-in run through over a MemoryStore with a ManualClock. Mutating the replay check, enrolment from a password, link expiry, the last-factor rule, the breached list or the audit chain each fails tests. A new fuzz target over every record parser and the text a person types (`fuzz/records_fuzz.cpp`), run here under ASan with a stand-in driver: 400,010 inputs, no crash. All green under `debug`, `release`, `asan` and `tsan`.

## 2026-10-18: P3, the store on one node (not committed)

- **Store** (`src/store/`): `Store`, the interface (get, find by a unique index, list, put and remove with an optional expected version, final removals with kept tombstones, per-record versions), `SealedStore` on disk, and `MemoryStore` in `tests/fakes/`. One log per table under `<state>/store/`, after Macha's sealed journal: a file header sealed under the table's data key, so a wrong keyring is refused before any frame is judged; one AES-256-GCM frame per change, bound to the table, the epoch and the previous frame's tag, so frames cannot move between tables or files, be reordered, dropped from the middle or replayed; every write synced before it is acknowledged, and cut back off the file if it fails part way.
- **Recovery**: a torn tail (nothing that looks like a frame after the break) is cut at open and logged; damage with frames after it stops the open, naming the file and the byte, after Macha's pack recovery but failing closed. A table whose failed write could not be cut back refuses writes until restart.
- **Compaction and keys**: a table more than half superseded past 1 MiB is rewritten whole under its current data key and renamed over the old, after Macha's pack compaction. `rotate()` makes a new data key epoch, saves the keyring before anything is sealed under it, and compacts. The first open of a table makes its data key.
- **Indexes**: declared per table, derived from the record value, unique, rebuilt at every open.
- **Not lifted from Macha**, and why: the rest of `LocalStore` and the ledger, which serve content-addressed objects placed by a DHT (`code-style.md`, "From Macha").
- **Ports**: `Files` gained `append`, `truncate` and `remove`. `crypto::sha256`, and 16- and 64-bit fields in `ByteReader`/`ByteWriter`.
- **Service**: `main` opens the store's 14 tables after the keyring and before it listens.
- **Tests**: 247 unit tests, among them a contract suite run against `SealedStore` and `MemoryStore` alike, every truncation of a log, damage, reordering, replay, a log moved to another table, another keyring, a failed write, a failed cut-back, compaction (and a failed one), rotation (and one whose keyring cannot be saved), and a torn tail on a real disk. The table log has a fuzz target (`fuzz/store_log_fuzz.cpp`), run here under ASan with a stand-in driver. All green under `debug`, `release`, `asan` and `tsan`.

## 2026-10-18: P2, crypto and keys (not committed)

- **Crypto** (`src/crypto/`, one thin layer over OpenSSL 3): AES-256-GCM seal and open with associated data and a random nonce from the `Random` port; HKDF-SHA256; Argon2id (OpenSSL 3.2+) with RFC 9106's second recommendation as the default and bounds on stored costs; ES256 and Ed25519 signing keys with PKCS#8 export and import, raw public keys (the uncompressed P-256 point, for a JWK) with an on-curve check, and JOSE-form signatures; constant-time comparison. Each is tested against its published vectors: the GCM specification's AES-256 cases, RFC 5869, RFC 9106, RFC 8032 and RFC 6979.
- **Memory**: `SecureBytes` and `Secret` hold their bytes in `core/secure_memory`, pages of their own that are locked into memory, kept out of core dumps on Linux and wiped when freed. Not OpenSSL's secure heap, because OpenSSL's Argon2id then takes its whole 64 MiB from that heap and fails; found by the init test. `Random` gained `fill`, so a key is made where it lives.
- **Keys** (`src/keys/`): the keyring file (`<state>/keyring`): a header saying where the master key comes from, then the data keys sealed whole under a KEK derived from the master key by HKDF, salted with the keyring's random id, with the header as associated data. Data keys per name and epoch, rotation, adding a key made elsewhere (for P8's join), and re-keying under a new master key. Written atomically (temporary, fsync, rename or link, directory fsync) and never replaced by init. The format's two parsers have a fuzz target (`fuzz/keyring_fuzz.cpp`), which also checks every parse writes back to the same bytes.
- **Master key**: from the systemd credential `lugh-master-key` in `$CREDENTIALS_DIRECTORY`, or from a passphrase of 16 characters or more typed at start and stretched by Argon2id. `lugh init` writes a new key to standard output for `systemd-creds encrypt`, refusing a terminal, and saves the keyring only once the key has gone; `lugh init --passphrase` asks twice. The service opens the keyring before it listens, and will not start without it.
- **Ports**: `system::Files` (`SystemFiles`, `MemoryFiles`) and `system::Console` (`SystemConsole`, `ScriptedConsole`). The IoC check now also refuses POSIX file calls, terminal calls and the process's memory outside the adapters.
- **Config and CLI**: `state.directory` (`LUGH_STATE_DIRECTORY`, `--state-directory`), the `init` command and `--passphrase`. `init` needs no TLS pair.
- **Deploy**: the unit passes `--state-directory /var/lib/lugh`, loads `LoadCredentialEncrypted=lugh-master-key:/etc/credstore.encrypted/lugh-master-key`, and sets `LimitMEMLOCK=16M`. `host-setup.sh` makes `/var/lib/lugh` (0700, lugh) and `/etc/credstore.encrypted` (0700), and warns while the credential is missing. `scripts/dev-init.sh` makes a development keyring and credential under `config/dev/`.
- **Tests**: 185 unit tests; a new `init` ctest that runs the real binary through init and start with a credential, with a passphrase, with each wrong, and with a terminal on standard output; the shutdown test now runs init first. All green under `debug`, `release`, `asan` and `tsan`.
- **Docs**: `architecture.md` (encryption at rest as built), `code-style.md` (key material, OpenSSL's secure heap, the new ports, the IoC rules, the test vectors), `README.md` (running with a keyring, and `lugh init` on a node).

## 2026-10-18: P1, skeleton (committed as `700092b`)

- **Build**: CMake 3.23+ with the presets `debug`, `release`, `asan`, `tsan` and `fuzz`; `lugh_core` (static), `lugh` and `lugh_tests`; `-Wall -Wextra -Wpedantic -Werror` and Clang's thread-safety errors on by default; hardening on by default (`_FORTIFY_SOURCE=3` outside Debug and sanitizers, `_GLIBCXX_ASSERTIONS`, libc++ fast hardening, `-fstack-protector-strong`, `-fstack-clash-protection` where it exists, CET or PAC/BTI by architecture, PIE, and `relro`/`now`/`noexecstack` on Linux), each flag probed under `-Werror` first because Apple's clang accepts some and then warns they did nothing. Boost 1.87+, OpenSSL 3, yaml-cpp, GoogleTest, Python 3.
- **Service**: Beast over TLS 1.3 and nothing older, with no plaintext listener and the TLS pair required by the config loader; a handshake timeout; the security headers (HSTS, nosniff, CSP, Referrer-Policy) set on every response after the middleware; `Server: Lugh` and no version anywhere a stranger can read it. The router with open routes, path parameters, 404/405 and per-address rate limits; `/health` and `/ready` saying ok and nothing else. `ClientAddress` trusts no proxy unless `proxy.trusted_networks` names it. Layered config (file, `secrets.yaml`, `LUGH_*`, CLI) with unknown keys warned and bad values refused naming their source. `Secret` (`core/secret.h`): a type that converts to nothing, so a secret cannot reach a log line, with wiping and constant-time comparison. Ports `Clock`, `Random`, `Environment` with system adapters. Core dumps refused by `main`.
- **Tests**: 89 unit tests; the shutdown test (makes its own certificate, speaks TLS, SIGTERM and SIGINT exit 0 within 5 s); the IoC check. All green under `debug`, `asan` and `tsan`. HTTP tests run the real server on port 0 over TLS with an in-process self-signed certificate (`tests/helpers/test_certificate.h`), and prove TLS 1.3 is negotiated, TLS 1.2 and plaintext are refused, and the headers are present. End to end: `scripts/dev-cert.sh` then `./build/lugh --config config/config.yaml`; `curl -sk` sees `{"status":"ok"}`, `--tls-max 1.2` fails the handshake, `http://` gets nothing.
- **Fuzz**: `fuzz/cli_fuzz.cpp` and the `fuzz` preset with a short ctest run per target. Not built here (Apple's clang has no libFuzzer).
- **Deploy**: `deploy/lugh.service` (user `lugh`, `CAP_NET_BIND_SERVICE` only, `StateDirectory=lugh`, `LimitCORE=0`, blackraven-admin's sandbox) and `deploy/host-setup.sh` (user, config and TLS directory permissions). `cmake --install` installs binary, config, docs and unit, runs host setup and restarts.
- **Docs**: `docs/code-style.md` (the rules, the Secrets section, IoC, errors, logging, tests, build, and the lifted-from tables: blackraven-admin for nearly all of it, AthenaSIP's `tls_context` for TLS), `README.md`, `.gitignore` (build trees, `config/dev/`, `*.pem`, `*.cred`, `secrets.yaml`, `CLAUDE.local.md`).

## 2026-10-18: P0, initial architecture (not committed)

- **Docs**: `docs/architecture.md` sets out the design as understood: the OAuth 2/OIDC, management API, LDAP and C++ library surfaces; the store built on Macha's sealed journal, packs and replication; the T.O.M.S styling for the dashboard; blackraven-admin's conventions; the security model; and the open questions.
- **TODO**: `ACTIVE.md` and `COMPLETE.md` created, with the phase plan P1 to P12.
