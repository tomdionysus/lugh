# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETE.md` with the date and the outcome.

## Resume here

2026-10-18: **P5 is done** (COMPLETE.md), not committed, and neither are P2 to P4. P1 is committed and pushed (`700092b`). `/api/v1` serves the directory, factors, enrolment links, policies and the audit log, but nothing resolves a caller yet, so it answers 401 to everyone. `lugh init` is genesis: root, with a random password shown once, the only credential there is. Next: P6, OAuth 2 and OIDC, with the sign-in and enrolment pages (root's first sign-in among them), sessions (async like everything else; the hashing pool is already in place), an admission limit on sign-ins in front of the hashing pool, scopes granted through groups (`administrators` holding every one), and the API taking sessions and OAuth tokens.

P4, as left: the directory and sign-in work end to end in the tests; P5 put the directory behind the API, and P6 puts sign-in behind its pages.

P3, as left: the store opens its 14 tables at start; P4 gave the directory's tables their indexes.

P2, as left: The `crypto/` layer, the keyring and `lugh init` build clean under `-Werror`, and `ctest` passes under `debug`, `release`, `asan` and `tsan`. The `fuzz` preset is still not built here: Apple's clang has no libFuzzer, and Homebrew's LLVM is not installed (`brew install llvm`, then `CXX=$(brew --prefix llvm)/bin/clang++ cmake --preset fuzz`). The keyring fuzz target was run instead under ASan with a stand-in driver. Next: P3, the store, on one node, using the keyring's data keys.

Not yet tried on Linux: `LoadCredentialEncrypted=`, `LimitMEMLOCK` and `MADV_DONTDUMP` are written for Ubuntu 26.04's systemd and kernel, and only the macOS paths have run. Check them on the first node.

## Waiting on the maintainer

- The open questions in `docs/architecture.md`, "Still open". None blocks P1. Question 1 (node identity) is needed by P8, question 2 (single-use grants) by P6 and P8, question 9 (second factor for everyone) was built as proposed in P4 (`mfa` for everyone by default, groups may only raise it), and is a setting, not code, if the answer differs, and question 14 (Lugh's hostname) by P13.

## Plan

Each phase ends with a green build, `ctest` passing under the `debug` and `asan` presets, the fuzz targets building, and a commit.

| ID | Phase |
|---|---|
| **P1** | Skeleton. CMake with presets (`debug`, `release`, `asan`, `tsan`, `fuzz`) and hardening flags; `lugh_core`, `lugh` and the tests; `.clang-format`; the config layering; the logger with secret redaction; `system/` ports; the IoC check; the HTTPS server (TLS 1.3) with `/health`; the shutdown test; the systemd unit and host setup; `docs/code-style.md` |
| **P2** | Crypto and keys. A `crypto/` layer over OpenSSL 3 (AEAD, HKDF, Argon2id, Ed25519/ES256, constant-time compare, secure memory), the key hierarchy, unsealing the master key from a systemd credential, `lugh init` |
| **P3** | The store, on one node. Copy `SealedJournal`, `LocalStore` and the ledger from Macha, strip the licence headers and adapt them to the conventions; sealed records with associated data; tables and derived indexes; compaction with DEK re-sealing; crash and torn-write tests |
| **P4** | Directory and authentication. Users, groups, memberships; Argon2id passwords; lockout and back-off; TOTP with replay refusal; recovery codes; enrolment links and forced enrolment; the audit log with its hash chain |
| **P5** | Management API. `/api/v1` CRUD, scoped permissions, ETags and the error format. Genesis: root and its one-time password, the only credential. The API opens to sessions and tokens in P6 |
| **P6** | OAuth 2 and OIDC. Applications (`apps`, `app_access`, role mapping, `private_key_jwt`, exact redirect matching); the SSO session; `acr`/`amr`, `max_age` and step-up; RP-initiated and back-channel logout; authorisation code with PKCE, client credentials, refresh rotation, the sign-in and consent pages, JWT access and ID tokens, JWKS and discovery, introspection, revocation, PAR, DPoP, the device grant. The API then switches to OAuth tokens |
| **P7** | Dashboard. The React SPA in T.O.M.S's styling, using the Lugh session cookie and a CSRF token against `/api/v1`, served from disk by the static handler, with a strict CSP; installed by `cmake --install` |
| **P8** | Cluster. Copy Macha's membership and merge, over a TLS 1.3 mTLS transport with per-node certificates; the join handshake that delivers the DEKs; full replication of every extent to every node, with anti-entropy catch-up; the merge rules (tombstones, versioned credentials, issuer-owned single-use grants); multi-node tests |
| **P9** | LDAP. The BER decoder (fuzzed), LDAPS and StartTLS, bind, search with limits, rootDSE, the generated tree |
| **P10** | C++ library. `lugh_client` with public headers in `include/lugh/` and a CMake package config; `lugh::client::RelyingParty` (code flow, callback, ID token and back-channel logout verification); offline access token verification; client credentials and device flows; an example subproject |
| **P11** | WebAuthn and passkeys, the `phr` level, and app passwords for LDAP |
| **P12** | Hardening pass. Fuzzing campaigns, a review of the systemd sandbox, key rotation drills, a threat model document, an external review checklist |
| **P13** | SSO rollout, each in its own repository: blackraven-admin first (it is the smallest, and needs a `service` caller kind), then T.O.M.S (`IAuthProvider` redirect plus the `hub` service account), AthenaSIP admin, and Macha (a `CredentialValidator`, provisioning by `sub`, the device grant for the TV app). Each keeps a break-glass local account |
