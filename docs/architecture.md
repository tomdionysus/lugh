# Architecture

Lugh is an authentication and directory server, and the single sign-on for every Blackraven project (T.O.M.S, blackraven-admin, Macha, AthenaSIP and those that follow). It holds the identities of people and services, authenticates people with two factors (a password and a second factor, or a passkey), and issues tokens that the applications it has been told to allow can trust. It speaks OAuth 2 (with OpenID Connect on top) to applications, a RESTful management API to administrators and automation, and a limited, read-mostly LDAP to legacy software that only knows how to bind and search. It also ships a native C++20 library, so a C++ project that includes Lugh as a subproject can authenticate users and verify tokens in process. Lugh is a security product first: every byte is encrypted in flight and at rest, every parser is fuzzed, and the process runs with the least privilege the host can give it.

Lugh is the top of a stack of three (the maintainer, 2026-11-03): **Dannan** (`../dannan`) is the network layer, nodes, membership, the transport, node identity and key custody, and the primitives every project shares (crypto, secure memory, the byte codec, durable files, time sources, the thread-safety contract, logging); **Dagda** (`../dagda`) is the replicated store; **Lugh** is the directory and its sign-in. Lugh uses Dannan as its network layer and Dagda as its datastore, and no code is duplicated between the three. What each owns, and the seams between them, are in `../dagda/TODO/2026-11-03-stack.md`; the maintainer's decisions of 2026-11-04 are in `TODO/ACTIVE.md`. A Lugh cluster is a Dannan cluster: `lugh-node` is a Dannan node, one process per node, and Lugh's state is Dagda's.

This document began as the design of 2026-10-18, before any code existed. What is built is said where it is; what is still to come says so.

## What it does

| Surface | Who uses it | What it offers |
|---|---|---|
| OAuth 2 / OIDC | Allowed applications, browsers, services | Single sign-on, second factor, consent, access/ID/refresh tokens, back-channel logout, token introspection and revocation, discovery and JWKS |
| Management API | The dashboard, administrators, automation | CRUD over users, groups, applications, factors, keys, policies; sessions; the audit log; cluster health |
| Dashboard | Administrators | A React admin interface over the management API, served by Lugh itself |
| LDAP | Legacy software (mail servers, NAS boxes, VPNs, Linux PAM/SSSD) | Simple bind over TLS, search over users and groups, rootDSE. Read only |
| `lugh` C++ library | C++ projects that add Lugh as a subproject, first of all the Blackraven projects | A drop-in OIDC relying party (sign-in, callback, token verification against cached JWKS, back-channel logout), the other OAuth client flows, and optionally in-process authentication against an embedded store |

Lugh is not a general-purpose LDAP server, a certificate authority for the outside world, or a SAML IdP (SAML stays out unless it is asked for).

## Components

```
               browsers / apps          admins           legacy clients
                     |                    |                    |
                 HTTPS :443          HTTPS :443           LDAPS :636
                     |                    |                    |
             +-------+--------------------+-------+     +------+------+
             |  http (Beast, TLS 1.3)             |     | ldap (BER)  |
             |  /oauth2  /.well-known  /api  /    |     | bind search |
             +--+-----------+----------+-----+----+     +------+------+
                |           |          |     |                 |
             oauth        api     dashboard (from disk)        |
                |           |                                  |
             +--+-----------+----------------------------------+--+
             |  authn: passwords, TOTP, WebAuthn, lockout, policy  |
             |  directory: users, groups, apps, attributes         |
             |  tokens: signing keys, JWT, opaque handles          |
             |  audit: hash-chained, append only                   |
             +-------------------------+---------------------------+
                                       |
             +-------------------------+---------------------------+
             |  Dagda: lugh/scope (every node), lugh/secrets       |
             |  (Lugh nodes), node-local spaces; sealed, merged     |
             |  (until then: Lugh's frozen sealed store + keyring)  |
             +-------------------------+---------------------------+
                                       |
             +-------------------------+---------------------------+
             |  Dannan: nodes, membership, mTLS transport, node     |
             |  identity and key custody, the scope seam            |
             +-----------------------------------------------------+
```

### Backend (`lugh`)

One C++20 binary, `lugh-node`, built from the static library `lugh` and the composition root `tools/lugh_node.cpp`. The layout is the stack's (`CONTRIBUTING.md`, "Layout").

| Subsystem | Does |
|---|---|
| `lugh/http/` | Boost.Beast server over Asio with OpenSSL, TLS 1.3 only. Router, rate limiter, security headers, request size and time limits, the static file handler for the dashboard. HTTP stays each hosted system's own (the maintainer, 2026-11-04) |
| `lugh/oauth/` | Authorisation, token, introspection, revocation, PAR, device and userinfo endpoints; discovery and JWKS (P6) |
| `lugh/api/` | The management API, `/api/v1/...` |
| `lugh/ldap/` | LDAPv3 listener, a second front end on the directory: a bounded BER decoder, bind, search, compare, add, modify, delete, rename, Password Modify, rootDSE. Nothing that would make it a general LDAP server (P9, `TODO/2026-11-04-ldap.md`) |
| `lugh/authn/` | Credential verification and the sign-in state machine (password, then second factor), lockout, rate limits, password policy, TOTP and its HMAC-SHA-1 |
| `lugh/directory/` | Users, groups, applications, attributes, membership, the mapping to LDAP DNs and OIDC claims |
| `lugh/tokens/` | Signing keys and their rotation, JWT encoding and verification, opaque token handles (P6). Token verification stays Lugh's; other systems verify through a Lugh plugin (the maintainer, 2026-11-04) |
| `lugh/audit/` | The append-only, hash-chained audit log |
| `lugh/store/`, `lugh/keys/` | The sealed table store and the keyring. Frozen until Dagda carries Lugh's spaces, then deleted (the maintainer: "Keep the store until Dagda") |
| `lugh/crypto/` | Only what is Lugh's: the sealed-value framing over Dannan's AES-GCM, and the stretch over Dannan's Argon2id. Everything else is Dannan's (`dannan/identity/`) |
| `lugh/system/` | Ports for the environment, files and the console, and their adapters. Time, randomness and logging are Dannan's |
| (Dannan) | Nodes, membership, the transport, node identity, key custody, the scope seam (Lugh installs its `ScopeSource`), the byte codec, durable files, time sources, the thread-safety contract, logging (P8 hosts Lugh on Dannan's `Context`) |

### Concurrency

Lugh is asynchronous from the socket to the disk (the maintainer, 2026-10-18), in Dannan's callback shape (the maintainer, 2026-11-03: "Lugh goes callback style"). Every operation that waits takes its arguments, a deadline, the caller's executor and `done`; `done` is posted to that executor exactly once, with the answer or, when the deadline passes first, what the operation says then, and never called inline (`lugh/core/completion.h`). An operation of several steps is one shared state whose steps start one another (`lugh/core/steps.h`); nothing holds a thread while anything waits. A read that could not happen answers `failed`, never "absent"; a change past its deadline says it may yet be made. Two small pools take the only work that cannot help but block: `blocking` for system calls on regular files and for the console, and `hashing` for Argon2id, whose two threads bound the memory sign-ins can take under the unit's `MemoryMax`. The audit chain is appended from a queue, one write in flight, so it has no gaps or forks without anything held across a write. The frozen store, keyring, files and console keep their coroutines until Dagda replaces them, reached through `lugh/store/store_calls.h`; the node's start-up, which runs them in sequence, is the one other coroutine.

### Library (`lugh_client`, and optionally `lugh_embedded`)

A separate, installable target with real public headers under `include/lugh/` and a CMake package config, so another project can `add_subdirectory(lugh)` or `find_package(lugh)`. Here Lugh deliberately differs from its siblings: Macha's `macha_core` is private and installs no headers, and blackraven-admin has no `include/` directory. A library for others needs a stable public face.

- **`lugh_client`** (always): fetches and caches discovery and JWKS from a Lugh cluster; verifies access and ID tokens locally (signature, `iss`, `aud`, `exp`, `nbf`, sender constraint); runs the authorisation code + PKCE, client credentials and device flows; introspects opaque tokens; calls the management API. It depends on OpenSSL and Boost only.
- **`lugh_embedded`** (option, open question): the host process joins the cluster as a non-serving node holding a replica of the directory, so it can authenticate a user name and password locally with no network round trip. That replicates sealed credentials into another process, so it would need its own threat model before anyone builds it.

### Frontend (`dashboard/`)

React 19, React Router 7 in SPA mode, Vite 7 and TypeScript 5.9, laid out like blackraven-admin's `dashboard/app/` (`screens/`, `components/` with paired `.css`, `layouts/`, `hooks/`, `lib/API.ts`). The look follows T.O.M.S:

- Plain CSS on custom properties in `app.css`, with no component library: `--bg #0c0e10`, `--surface #15181c`, `--surface-raised #1c2026`, `--border #272c33`, `--text #e8ebee`, `--text-muted #939da7`, `--good #00cc44`, `--warn #ffb020`, `--bad #ff4d4d`, with `--radius 14px` and `--gap 16px`.
- Self-hosted Roboto Variable for body text, one display face for the wordmark only, translucent cards, pill navigation, uppercase letter-spaced section labels, and `color-mix()` tints. Dark only.
- An admin tool needs things T.O.M.S never had, mainly dense tables, forms, confirmation dialogs and diffs of policy changes. They are built in the same tokens and idioms.

The dashboard is same-origin with Lugh, so it does not hold a token in the browser at all. It sends the user through the ordinary `/signin` flow, which sets the Lugh session cookie, and calls `/api/v1` with that cookie plus a CSRF token. The API treats a session the same as a bearer token: the caller's groups and `acr` decide what it may do, and the dashboard requires `phr`. The same `/api/v1` accepts bearer and DPoP tokens from automation. There is no private back door and no token for a cross-site script to steal, which is the same backend-for-frontend shape the Blackraven projects use (see Single sign-on).

The dashboard is served from disk, as in T.O.M.S and blackraven-admin (the maintainer, 2026-10-18):

- `npm ci && npm run build` writes `dashboard/build/client/`, and `cmake --install` copies it to `/usr/local/share/lugh/dashboard`. Install fails with an explanation if the build is missing, and it deletes the old copy first, because Vite fingerprints its assets.
- The static handler serves only that directory, configured by `static.directory`. `/api`, `/oauth2`, `/signin`, `/.well-known`, `/health` and `/ready` are reserved, so a wrong path there gets a JSON 404, never `index.html`.
- The installed copy is owned by root and read-only to the `lugh` user. `ProtectSystem=strict` makes it read-only to the service in any case.
- The handler refuses symlinks, dot-files and any path that resolves outside the directory.
- Every response carries a strict CSP (`default-src 'self'`, no inline script), `X-Content-Type-Options: nosniff` and `frame-ancestors 'none'`.

In development, Lugh runs with the static handler off, Vite runs on its own and proxies the reserved paths to it, as blackraven-admin does.

## Data

### The store

**On the stack (P8):** Lugh's state is Dagda's (the maintainer, 2026-11-03, settled 2026-11-04). Two domains: `lugh/scope`, with every node a member, for what every hosted system's writes are checked against (who holds which scope), and `lugh/secrets`, with Lugh nodes only, for credentials, factors, sessions and grants. Sessions are replicated across Lugh nodes, so a session works at any of them; single-use grants and TOTP steps are node-local or held under a lease. Dagda seals at rest under Dannan's key custody, binds each value to its domain and id, never rolls a space back, and merges; Lugh brings its merge rules (below) and checks its ETags inside Dagda's `mutate_local`. Every write carries a durability level the caller picks (Ephemeral, Persisted on one node, Replicated on k nodes, Durable on every available replica): credential and factor changes and revocations are Replicated, and where a write's evidence names nodes still pending Lugh answers "applied, n nodes pending" and clears it from the write's ticket. Lugh has no store, keyring or sealing of its own then.

**Until then (built, P3, frozen):** each table is one log, `<state>/store/<table>.log`. It has a header sealed under the table's data key, then one AES-256-GCM frame per change, each bound to the table, its data key epoch and the frame before it. Every write is appended and synced before it is acknowledged. A torn tail is cut at the next open. Damage in the middle stops the open, because a record dropped from a security table might be a revocation. Records are held in memory sealed and opened on each read, the indexes are rebuilt at every open, and a table is compacted (rewritten under its current data key, then renamed over the old) once it is more than half superseded or its key is rotated. A removal leaves a tombstone kept for ever, and a removed key can never be written again. Every record has a version, which the API's ETags use.

Tables are `users`, `credentials`, `factors` (TOTP secrets, WebAuthn credentials, recovery codes), `app_passwords`, `groups`, `memberships`, `apps`, `app_access`, `consents`, `sessions`, `grants` (codes, refresh tokens, device codes), `signing_keys`, `policies` and `audit`. Secondary indexes (user name, email, client ID, group name) are derived and rebuilt from the tables, never trusted as authoritative.

As built for the directory and authentication (P4): a user is keyed by a random 128-bit ID and found by name or address through the `users` table's unique indexes, both folded to lower case on the way in, so `Alice` and `alice` cannot both exist. A group is found by name the same way. Because a removal is final and its key is never used again, anything that can be removed and then made again gets a key of its own each time: a membership is `<group>/<user>/<instance>`, a factor `<user>/<kind>/<instance>`. A group's policy is never removed; clearing it writes "none". The password is one record per user in `credentials`, and its version is the credential version the merge will compare. The audit log is one record per entry in `audit`, keyed by a zero-padded sequence number. Every write the directory makes carries the version it read, so two administrators editing one user cannot silently overwrite each other.

### Consistency, and where eventual is not good enough

Dagda, like Macha before it, is availability-first: every node accepts writes and partitions merge later. That is right for most of a directory, such as a user's display name or a group's description. It is wrong for anything where a lost or merged write is a security hole, and these are the merge rules Lugh brings to Dagda (tombstones kept for ever: the maintainer, 2026-11-04):

| Data | Rule |
|---|---|
| Ordinary attributes | Merge as Macha does, with deterministic last-write-wins per field |
| Revocations, disabled accounts, deleted keys and clients | A grow-only tombstone set. A merge can never undo a revocation or bring a deleted thing back |
| Password and credential changes | Versioned. The merge keeps the newest version and also revokes the sessions of every losing branch |
| Authorisation codes, refresh token rotation, device codes, WebAuthn challenges, TOTP replay windows | Single-use, so they must not be redeemable twice on two sides of a partition. Each is owned by the node that issued it (its node ID is in the handle) and redeemed only there, with other nodes forwarding the request. If the owner is unreachable, the grant fails closed |
| Lockout counters, rate limits | Per node, summed by gossip. A partition loosens lockout to at most N times the limit, never removes it |
| Signing keys | Created on one node and published to the others before use, then announced in JWKS before any token is signed with them |

This needs testing hardest of anything here, on Dannan's in-process cluster fixture. Two limits are accepted as stated (the maintainer, 2026-11-04): the partition bound (lockout loosened to at most N times the limit) and the trust boundary (what a node of the cluster may do).

### Encryption at rest

**On the stack (P8):** Dagda seals Lugh's domains, and the keys come from Dannan's node key custody (each node's key and seal root under a systemd credential or an Argon2id-stretched passphrase, never on disk in clear), reached through the `Context` (`derive_key`, `derive_local`). Lugh holds no key at rest of its own. Signing keys for tokens are sealed in `lugh/secrets`.

**Until then (built, P2, frozen):**

- **Master key:** 32 bytes, never stored in clear. `lugh-node init` makes it and writes it to standard output, which is piped to `systemd-creds encrypt`; the unit unseals it at each start with `LoadCredentialEncrypted=lugh-master-key` (bound to the TPM where there is one), and Lugh reads it from `$CREDENTIALS_DIRECTORY`. On a host without systemd credentials, `lugh-node init --passphrase` stretches a typed passphrase with Dannan's Argon2id instead, and every start asks for it. The master key is used once, to derive the KEK with Dannan's HKDF, and then wiped.
- **The keyring:** the data keys (one per table and epoch) live in `<state>/keyring`, a file of their own outside the store they protect, sealed whole with AES-256-GCM under the KEK. Its header (how to find the master key: credential, or passphrase with its Argon2id costs and salt) is bound in as associated data, so a wrong key and an altered file are refused alike. It is written with Dannan's durable create (`init` never replaces one) or replace, so a crash leaves the old file or the new one. The KEK and data keys are held in Dannan's locked memory, kept out of core dumps and wiped when freed.
- **Rotation:** rotating a data key starts a new epoch, and compaction re-seals old records into it.
- **Credentials:** password hashes are Argon2id, stored inside the sealed record. A copy of the store without the master key therefore gives an attacker neither records nor hashes.

## Applications

An application is an OAuth client that an administrator has registered and allowed. Only allowed applications can send a user to Lugh to sign in, and Lugh will only ever redirect a user back to an address it has on file for that application.

### What an application has

| Field | Meaning |
|---|---|
| `client_id` | Random and public, e.g. `app_7f3k...`. Never reused after deletion |
| Name, icon, home URL | Shown on the sign-in and consent pages, so the user can see who is asking |
| Kind | `web` (a server-side backend: confidential), `spa` or `native` (public, PKCE only), `service` (machine to machine, no user), `api` (a resource server: it defines scopes and is an `aud`, and does not sign users in itself). One registration can be both a client and an `api`, as T.O.M.S is |
| Client authentication | Confidential clients use `private_key_jwt` (preferred; the app holds the private key and Lugh holds the public one) or `tls_client_auth`. `client_secret_basic` is allowed only if policy permits; the secret is shown once, stored as an Argon2id hash, and rotated with an overlap period |
| Redirect URIs | Exact matches only: no wildcards, no prefix matches. `https` only, except loopback `http://127.0.0.1/...` for native apps, where RFC 8252 requires the port to be ignored because the app picks it at run time |
| Post-logout and back-channel logout URIs | Where Lugh sends the user after sign-out, and where it POSTs the signed logout token |
| Grants | The subset of authorisation code, refresh token, device code and client credentials the app may use |
| Scopes and audience | What the app may ask for (`openid`, `profile`, `email`, `groups`, `offline_access`, plus app-defined API scopes) and the `aud` its access tokens carry |
| Who may sign in | `app_access`: the groups whose members may use this app. Anyone else is refused after authenticating, and no code or token is issued |
| Role mapping | Groups mapped to the app's own role names, sent as a `roles` claim for that audience only. Each project keeps its own role model: Macha's `media_viewer` and `manage_users`, AthenaSIP's `manage-realms`, T.O.M.S's `operator` and `hub` |
| Assurance | The minimum `acr` the app requires (see Two-factor authentication) and a `max_age` after which the user must sign in again |
| First party | First-party apps skip the consent screen, because the administrator granted consent by registering them. Third-party apps always show it |
| Sender constraint | Whether tokens must be bound by DPoP or mTLS |
| Token lifetimes | Access token (default 5 minutes), refresh token (idle and absolute), ID token |
| State | `enabled` or `disabled`. Disabling an app revokes every grant and token issued to it |

### Rules

- Applications are created only by an administrator, through the dashboard or `/api/v1/apps`. Dynamic client registration (RFC 7591) is off, and there is no way to turn it on.
- An unknown `client_id`, a disabled app, or a `redirect_uri` that does not match exactly gets an error page on Lugh. Lugh never redirects to an address it cannot vouch for.
- Every application change is audited, with a before-and-after diff shown in the dashboard.
- Each app sees a stable `sub` for a user that never changes, even if the user name or email changes. Applications key their local user records on `sub`, never on email.

## Single sign-on for Blackraven projects

The user signs in once, at Lugh. Lugh keeps its own session (`__Host-lugh_session`), and every other allowed app the user opens bounces through `/oauth2/authorize` and back without a prompt, provided:

- the user is still allowed into that app;
- the session's `acr` meets the app's minimum;
- the session is younger than the app's `max_age`.

If any of these fails, Lugh asks for exactly what is missing (usually the second factor) and no more.

### How a project plugs in

Every Blackraven server is C++, so each one links `lugh_client` as a subproject and uses `lugh::client::RelyingParty`. It does the OIDC work:

- builds the authorisation request with `state`, `nonce` and PKCE;
- handles the callback and redeems the code using the app's `private_key_jwt`;
- verifies the ID token against cached JWKS and checks `iss`, `aud`, `exp`, `nonce` and `acr`;
- verifies back-channel logout tokens.

The project then does what it already does after a password login: mint its own opaque session and set its own cookie. For these server-side projects the browser never sees a Lugh token. This "backend for frontend" shape fits every project's existing session design, so the change is to the login step only. Macha's browser, mobile and TV clients are the exception: they are public clients that hold a Lugh token themselves and present it to a node:

| Project | Kind of app | How it signs in through Lugh | Notes |
|---|---|---|---|
| T.O.M.S dashboard | `web` | OIDC code flow in `toms_api`, which then sets `toms_session`. It fits the existing `IAuthProvider` `Method::redirect` path | The build node kiosk keeps loopback trust and never touches Lugh. The site is plain HTTP over WireGuard, so redirect URIs need TLS on the site (open question) |
| T.O.M.S `hub` account | `service` calling T.O.M.S as an `api` | Client credentials from blackraven-admin, with an access token for `aud=toms` scoped `toms:dns` | Replaces the hub password that blackraven-admin keeps in `secrets.yaml`. toms verifies the JWT offline with `lugh_client` |
| blackraven-admin | `web` | OIDC code flow in the backend, which then sets `blackraven_session` | `Caller` needs a `service` kind for client-credentials callers |
| Macha nodes | `api` (`aud=macha`) | A Macha client gets a Lugh access token for `aud=macha`, then presents it to any Macha node at `POST /api/v1/session`. The node verifies it offline with `lugh_client` through a new `CredentialValidator` and mints a Macha session | The user is provisioned into Macha's gossiped user table on first sign-in, keyed by `sub`. Anonymous sessions are unchanged; Lugh only upgrades an anonymous session to a named one |
| macha-client (browser) | `spa` | Authorisation code and PKCE, then hand the token to a node as above | |
| macha-client-rn (mobile) | `native` | Authorisation code and PKCE through the system browser (AppAuth), returning on a claimed HTTPS redirect (universal or app link) | The token stays in `expo-secure-store` |
| macha-client-rn-tv (Android TV) | `native`, device grant enabled | Device authorisation grant: the TV shows a code and a QR, and the user approves on a phone, with 2FA, at `/signin/device` | This also gets rid of typing a password with a remote. Its token should move to the Android Keystore |
| AthenaSIP admin API and athenasip-admin | `web` | OIDC code flow in AthenaSIP, which then mints its existing admin Bearer session | |
| AthenaSIP subscribers (phones, softphone) | none | Unchanged: SIP Digest against HA1 | OAuth cannot replace Digest for phones. Lugh could later provision SIP credentials, but that is not planned |

### Signing out and revocation

- **Signing out:** signing out at Lugh, or at any app that calls Lugh's end-session endpoint, ends the Lugh session. Lugh then sends an OIDC back-channel logout token to every app the session signed into, and each app deletes its own session for that `sid`. Every ID token carries `sid` so the app can make that link. There is no front-channel logout, because it depends on third-party iframes.
- **Disabling and resets:** disabling a user, removing them from an app's groups, or resetting their factors sends the same logout to every app and revokes their refresh tokens.
- **Bounded app sessions:** an app must not let its own session outlive the Lugh session it came from. The projects' sessions today last 7 days idle and 30 absolute, which is far longer than a Lugh session. So `RelyingParty` keeps the refresh token server-side and refreshes it on a bounded interval (default 15 minutes); a refresh that fails because the Lugh session or grant is gone ends the app session. Back-channel logout makes this prompt; the refresh makes it certain.

### When Lugh is unreachable

Each project keeps one break-glass local account, created from its own command line as today (e.g. AthenaSIP's `--add-user`), for when Lugh is down. Local password login is off for everyone else once a project is on Lugh. Sign-ins with the break-glass account are audited by the project and should alert.

## Two-factor authentication

Every person signs in with two factors: a password and a second factor, or a passkey with user verification, which is two factors in one. Service accounts, which use client credentials, have no password and no second factor; their key is their credential.

### Factors

| Factor | Details |
|---|---|
| WebAuthn and passkeys | Security keys and platform authenticators. With user verification, a passkey counts as phishing-resistant multi-factor on its own, so the user can skip the password entirely. Lugh stores the credential ID, public key, sign count, AAGUID and transports. A sign count that goes backwards is refused and flagged |
| TOTP | RFC 6238, SHA-1, 6 digits, 30-second steps, for compatibility with every authenticator app. One step of drift either way. A code already used (same or earlier step) is refused, so codes cannot be replayed. The secret is sealed under its own table DEK and shown only once, at enrolment, as a QR code |
| Recovery codes | Ten single-use codes, generated at enrolment, shown once, and stored as Argon2id hashes. Using one is audited and tells the user how many are left |
| Not offered | SMS and email codes, because of SIM swaps and phishable inboxes |

### Policy

Policy is set globally, then per group, then per app, and the strictest wins:

- **Assurance levels:** sessions carry an `acr` of `urn:lugh:acr:pwd` (password only), `urn:lugh:acr:mfa` (password and TOTP or recovery code) or `urn:lugh:acr:phr` (phishing-resistant: WebAuthn). The `amr` claim (RFC 8176: `pwd`, `otp`, `hwk`, `swk`, `user`, `pin`) records what was used.
- **The default** is `mfa` for everyone. Lugh's own dashboard, blackraven-admin and anything else that administers infrastructure require `phr`.
- **Step-up:** an app can ask for a higher level or a fresh sign-in with `acr_values` or `max_age`. Lugh prompts only for what is missing.

### Enrolment and recovery

- **Enrolment:** a new user signs in with a one-time enrolment link (from an administrator; the first administrator, root, comes from genesis instead), sets a password, and must enrol a second factor before any app gets a token. While a user is enrolling, the session is limited to enrolment. The first admin must enrol a WebAuthn credential, because the dashboard requires `phr`, so `lugh init` is not finished until that has happened.
- **Adding and removing factors:** adding or removing a factor requires re-authenticating with an existing factor, is audited, and notifies the user. Removing the last factor is refused while policy requires one.
- **Lost factors:** a user who has lost every factor uses a recovery code. Without one, an administrator resets the factors; the administrator must step up to `phr` to do so, and the reset is audited, revokes every session and token the user has, and makes them enrol again.
- **No device trust:** there is no "trust this browser for 30 days". The Lugh session is what carries the second factor, and it has an absolute lifetime.

As built (P4):

- **Enrolment starts only from a link.** Signing in with only a password never opens enrolment. If it did, a stolen password would be enough to enrol the thief's own authenticator. A person who set a password through a link and stopped before enrolling a factor needs a new link. Spending the link and setting the password happen together. The password is checked first, so a refused password does not use up the link.
- **TOTP:** a new secret counts only once a code from it has been typed back. Several TOTP factors may be enrolled. The last step used is stored in the factor's record. A second sign-in racing with the same code reads the same step and loses on the record's version.
- **Recovery codes:** each is 16 base32 characters (80 bits), shown as `abcd-efgh-ijkl-mnop`, with dashes, spaces and case ignored when typed. They are hashed with Argon2id at OWASP's lightest costs (19 MiB, two passes), because 80 random bits need no slow hash against guessing. The first four characters select the code's slot, so checking a guess costs one hash, not ten. New codes replace the old set only once they are stored. Recovery codes do not count as a second factor; they stand in for one.
- **Refusals look the same.** An unknown name, a wrong password, a disabled account, a service account and a person who is not enrolled all get the same refusal. Each still costs one Argon2id hash, so the time taken gives nothing away. The audit log records the reason. For an unknown name it records no name, because what is typed into the name box is sometimes a password.
- **Back-off:** per account, five free failures, then a wait of 1 second that doubles up to 15 minutes. Per address the free failures are twenty, because an office may share one address. Both are forgotten after an hour without a failure. A waiting caller is answered before any hashing, so it costs nothing. A wrong code counts against both, as a wrong password does.
- **Removing a factor:** a user's last confirmed TOTP factor cannot be removed while their policy needs more than a password. An administrator's reset first marks the user not enrolled, then removes their factors, so a reset that fails part way still stops sign-in. Re-authenticating before a change, notifying the user, and revoking sessions on a reset all need sessions, which arrive in P6.
- **Not yet:** a password change by its owner and step-up need sessions (P6); WebAuthn and the `phr` level arrive in P11. Until then the highest level anyone can reach is `mfa`, and P6 must refuse an app that requires `phr`.

### Limits

- **Attempts:** five wrong codes end the sign-in attempt, and the user starts again from the password. Repeated failures back off per account and per source address, as for passwords.
- **Partitions:** the TOTP "last used step" is a single-use record, so it follows the single-use rule in Data. A code cannot be replayed on the other side of a partition.

### LDAP and the second factor

An LDAP simple bind cannot carry a second factor. So for any user whose policy requires one, Lugh refuses their main password over LDAP. Instead, the user (or an administrator) creates **app passwords**:

- they are random, shown once and stored as Argon2id hashes;
- each is limited to LDAP and, optionally, to named source networks;
- each is named for the device that uses it, and can be revoked on its own.

LDAP service accounts work the same way: a service account has no password of its own, so an app password is the only thing it can bind with.

## Security

### In flight

- **Clients:** TLS 1.3 only on HTTPS, with HSTS. Certificates come from files the operator supplies, with ACME as an open question.
- **LDAP:** LDAPS on 636, or StartTLS on 389 with every operation except StartTLS refused until TLS is up. Plain-text simple bind is never accepted.
- **Between nodes:** TLS 1.3 with mutual authentication. Macha uses one shared cluster key and cannot revoke a single node, which is not acceptable for an identity server. Lugh gives each node its own key pair signed by a cluster CA that Lugh itself holds, so removing a node revokes its certificate and the others stop talking to it (proposed, open question 1).
- **Outbound:** calls such as webhooks and federation are TLS-verified with no option to turn verification off.

### OAuth profile

The profile follows the OAuth 2.1 draft and the OAuth 2.0 Security BCP (RFC 9700):

| Area | Rule |
|---|---|
| Grants | Authorisation code with mandatory PKCE (S256), client credentials, refresh token, device authorisation (RFC 8628). No implicit grant, no password grant |
| Redirect URIs | Matched exactly against the registered list |
| Requests | Pushed authorisation requests (RFC 9126) supported, and required for confidential clients if policy says so |
| Token binding | DPoP (RFC 9449) or mTLS (RFC 8705), so a stolen token is useless |
| Refresh tokens | Rotated on every use. Reusing an old one revokes the whole family |
| Access tokens | Short-lived JWTs (RFC 9068), or opaque handles per client. Signed with ES256 by default, because every client library supports it; EdDSA (Ed25519) is available per app for clients that do |
| Other endpoints | Introspection (RFC 7662), revocation (RFC 7009), discovery (RFC 8414 and OIDC Discovery), JWKS |
| OIDC | Core: ID token, userinfo, `nonce`, `acr`/`amr`, `max_age`. RP-initiated logout and back-channel logout |
| Client authentication | `private_key_jwt` or `tls_client_auth`, with `client_secret_basic` allowed only by policy. Public clients have no secret and must use PKCE |

### Authentication

- **Passwords:** Argon2id, with a minimum length and a breached-password check against a local list. The second factor is described in Two-factor authentication above.
- **Lockout and rate limits:** per account and per source address, using back-off rather than hard lockout so an attacker cannot lock users out on purpose.
- **Browser sessions:** `__Host-` cookies that are `Secure`, `HttpOnly` and `SameSite=Lax`, with server-side session records. CSRF tokens protect every form.
- **Comparisons:** every comparison of a secret is constant time.

### The process and the build

- **Compiler and linker hardening:** `-D_FORTIFY_SOURCE=3`, `-D_GLIBCXX_ASSERTIONS`, `-fstack-protector-strong`, `-fstack-clash-protection`, PIE, `-Wl,-z,relro,-z,now,-z,noexecstack`, plus `-fcf-protection` on x86-64 and `-mbranch-protection=standard` on arm64. blackraven-admin has none of these; Lugh turns them all on by default.
- **Warnings:** `-Wall -Wextra -Wpedantic -Werror`, plus Clang's `-Werror=thread-safety` as in Macha.
- **Sanitisers and fuzzing:** ASan/UBSan and TSan presets that run routinely, not only before a release. Every parser has a libFuzzer target: BER, JSON, JWT, HTTP request line and headers, form bodies, the LDAP filter grammar and sealed record frames.
- **systemd:** the unit uses everything blackraven-admin's does (`ProtectSystem=strict`, `NoNewPrivileges`, `MemoryDenyWriteExecute`, `SystemCallFilter`, `RestrictAddressFamilies` and the rest). It adds `CAP_NET_BIND_SERVICE` only for 443 and 636, `LoadCredentialEncrypted` for the master key (systemd 250 or later, which Ubuntu 26.04 has), `LimitCORE=0`, and a dedicated `StateDirectory`.
- **Secrets in memory:** wiped with `OPENSSL_cleanse` and never logged. The logger has a redaction type that secrets are wrapped in, so passing one to a log call does not compile.
- **Audit log:** every authentication, token issue, admin change and key operation goes to an append-only audit table. Each entry carries the hash of the one before, so deletion or editing is detectable, and the log can be exported for an external SIEM. As built (P4), each entry is SHA-256 over a context string, its fields and the previous entry's hash. `verify()` walks the whole chain and names the first entry that is missing, altered or out of order. For now there is one chain per node. P8 gives each node its own sequence, so that two nodes do not contend for one number. Long fields are cut to fit rather than refused, because an action that has happened is recorded whatever its detail says.
- **Dependencies:** system `find_package` only, as in blackraven-admin, with nothing new added without asking.

## HTTP surface

| Path | What |
|---|---|
| `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server` | Discovery |
| `/oauth2/jwks` | Public signing keys |
| `/oauth2/authorize`, `/oauth2/par`, `/oauth2/token`, `/oauth2/introspect`, `/oauth2/revoke`, `/oauth2/device`, `/oauth2/userinfo`, `/oauth2/logout` | OAuth and OIDC |
| `/signin/...` | The server-rendered sign-in, second factor, consent, enrolment and device-approval (`/signin/device`) pages. They are deliberately not part of the SPA, so they work with no JavaScript beyond one external WebAuthn script, which the CSP allows |
| `/api/v1/...` | The management API: JSON; the Lugh session cookie with a CSRF token (the dashboard) or bearer and DPoP tokens (automation); scoped permissions; `{"error":{"code","message"}}` on failure; ETags for optimistic concurrency |
| `/health`, `/ready` | Liveness and readiness, revealing nothing |
| `/` | The dashboard, from `static.directory` |

As built (P5), `/api/v1` covers users, groups, memberships, factors, enrolment links, policies and the audit log, and is described route by route in [api.md](api.md). Its scopes are `lugh:directory.read`, `lugh:directory.write`, `lugh:credentials.write`, `lugh:policies.write` and `lugh:audit.read`. Every route declares its scope in the router, so a handler never forgets to check one. Nothing resolves a caller until P6 brings sessions and OAuth tokens, so until then the API refuses everyone. `PATCH` and `DELETE` on a user or group need `If-Match`: `428` without it, `412` when it is stale. A field a route does not know is refused rather than ignored. Every route handler is a coroutine; see Concurrency below.

## LDAP surface

| Item | Scope |
|---|---|
| Operations | `BindRequest` (simple, over TLS only), `SearchRequest`, `CompareRequest`, `AddRequest`, `ModifyRequest`, `DeleteRequest`, `ModifyDNRequest` (a rename, never a move), `AbandonRequest`, `UnbindRequest`, `ExtendedRequest` for StartTLS, "Who am I?" and Password Modify (a user's own, bound with the main password). The paged-results and Assertion controls. Everything else gets `unwillingToPerform`. Writes are mapped onto the directory's own fields and need the API's scopes; the design is `TODO/2026-11-04-ldap.md` (the maintainer, 2026-11-04) |
| Tree | Fixed and generated from the directory: `dc=<domain>` with `ou=people` and `ou=groups`. Entries use `inetOrgPerson`, `posixAccount` and `groupOfNames` attributes, including `memberOf`. `posixAccount` needs `uidNumber`, `gidNumber` and `homeDirectory`, so Lugh allocates each user and group a stable number from a configured range and never reuses one |
| Filters | Equality, presence, substring, and/or/not, with bounded depth and size |
| Limits | Size, time and paging limits on searches |
| Access | Anonymous bind is off. Service accounts that may search are granted it explicitly. Users whose policy requires a second factor bind with an app password, never their main password |

## Configuration

YAML, layered as in blackraven-admin: `config.yaml`, then `secrets.yaml` beside it, then `LUGH_*` environment variables, then the CLI. Unknown keys are warned about and bad values are refused, naming their source. The master key never appears in any of these: it comes in as a systemd credential, or as a passphrase typed at start on a host without one (development on macOS, for instance), and nowhere else.

## Install and the host

`sudo cmake --install build-release` is the whole deployment, as in blackraven-admin:

- the binary goes to `/usr/local/bin/lugh`, the config to `/usr/local/etc/lugh`, the dashboard to `/usr/local/share/lugh/dashboard`, state to `/var/lib/lugh` (0700, owned by user `lugh`) and the unit to `/etc/systemd/system/lugh.service`;
- `deploy/host-setup.sh` then creates the user and sets permissions.

Docker is not used. A first node is initialised with `lugh init`, which creates the node's master key, the cluster CA (if open question 1 goes that way) and the first admin's one-time enrolment credential. Further nodes join with a one-time enrolment token and receive the DEKs over the join handshake.

## Repository layout

The stack's layout (`CONTRIBUTING.md`, "Layout"), identical in Dannan, Dagda and Lugh:

```text
lugh/<subsystem>/   the library: headers and sources side by side
lugh/include/lugh/  the public headers of the client library, and nothing else
lugh/test/          GoogleTest, flat, one binary (lugh_tests): the units, the IoC check, and
                    the process tests that run the real lugh-node; fixtures in fixtures/
lugh/fuzz/          libFuzzer targets, one per parser
tools/              lugh_node.cpp (the composition root, building lugh-node), and the
                    development certificate and keyring scripts
dashboard/          React admin dashboard (P7), installed beside the binary
config/             config.yaml, no secrets
deploy/             the systemd unit and host setup
docs/               how it works
TODO/               now and next (ACTIVE.md), and what shipped (COMPLETED.md)
```

The conventions are the stack's, in `CONTRIBUTING.md`: C++20, `.clang-format` (Google, 160 columns), `lugh::<subsystem>` namespaces, PascalCase types and snake_case everything else, `_`-prefixed private members, `#pragma once`, includes rooted at the repository (`"lugh/<subsystem>/x.h"`, `"dannan/<subsystem>/x.h"`), constructor injection with one composition root, Dannan's checked locks, and Dannan's warning set under `-Werror`. Lugh's two stated exceptions (the maintainer, 2026-11-04): it keeps CMake presets, and it runs the sanitizers at the end of every phase. There is no Python.

## Decided, 2026-10-18

- **The dashboard is served from disk**, installed to `/usr/local/share/lugh/dashboard`, as in T.O.M.S and blackraven-admin. It is not compiled into the binary.
- **Macha's code is copied into Lugh and adapted** (superseded 2026-11-03: Lugh uses Dannan and Dagda, which are written from their own designs, and copies nothing from Macha; `docs/provenance.md` records what P1 to P5 took).
- **Every node holds every extent** (superseded 2026-11-04: `lugh/scope` is on every node, `lugh/secrets` on Lugh nodes, by Dagda's placement).
- **No static credentials** (the maintainer, 2026-10-18). There is no bootstrap token, no key or password in a file or setting, and nothing else built in. At genesis, which is `lugh init` on a new cluster's first node, Lugh makes the user `root`, in the group `administrators`, with a randomly generated password. It shows that password once and stores only its hash. That password is the only credential a cluster is born with. Root's first sign-in goes from that password straight to enrolling a second factor, once. That is the one exception to "enrolment starts from a link" (`authn/genesis.h`). Every other administrator is made by root or by another administrator.

## Still open

1. ~~**Node identity**~~: Dannan's, per-node certificates from a cluster CA over keys in key custody, with CA-signed revocation (Dannan step 10, 09a525f).
2. **Single-use grants:** node-local or under a Dagda lease (the maintainer, 2026-11-04, "Lugh's design"). Which, for each kind of grant, is still to be designed with P6.
3. ~~**OIDC:** in scope from the start, or plain OAuth 2 first?~~ From the start (the maintainer, 2026-11-04; the P6 design is `TODO/2026-11-04-oauth.md`, which also settles question 2 for codes, device codes and refresh tokens).
4. **The C++ library's embedded mode:** the client side (`RelyingParty`, token verification, flows) is now required for SSO. Is the embedded mode, which holds a replica of the directory in the host process, still wanted? Full replication makes it simpler, but it puts every sealed credential into that process.
5. ~~**LDAP:** read-only bind and search, or writes?~~ Writable, mapped onto Lugh's model, with Password Modify for a user's own password (the maintainer, 2026-11-04, "level 2"; `TODO/2026-11-04-ldap.md`). Still open there: TLS 1.2 for old LDAP clients, and five smaller questions.
6. **Federation:** should Lugh sign users in through upstream identity providers (Google, Microsoft, another OIDC provider)? It is not planned here.
7. **Certificates:** ACME for the public TLS certificate, or operator-supplied files only?
8. **Target platform:** Linux (Ubuntu 26.04, GCC 15) as for blackraven-admin, with macOS for development only?
9. **Second factor for everyone:** `mfa` as the default for every person, with `phr` (WebAuthn) for infrastructure admin apps (proposed)? Or optional for some groups?
10. **T.O.M.S sites:** sites run plain HTTP over WireGuard. Do they get TLS for the OIDC redirect, or does T.O.M.S sign in through Lugh only at the hub?
11. **Break-glass accounts:** one local account per project with local login off for everyone else (proposed), or keep local login available as well?
12. **Macha:** the client gets a Lugh token and exchanges it at a node for a Macha session (proposed), or Macha accepts Lugh access tokens directly on every request?
13. **AthenaSIP subscribers:** leave SIP Digest entirely outside Lugh (proposed), or have Lugh hold and provision SIP credentials later?
14. **Where Lugh lives:** one public hostname for the whole fleet (e.g. `id.blackraven.co.nz`)? Each Blackraven app's redirect URI and the `iss` claim depend on it.
