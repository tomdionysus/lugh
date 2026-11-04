# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here

2026-11-04: **Aligning with Dannan and Dagda** on `feature/dannan-alignment`, one commit per step, nothing pushed (COMPLETED.md, "Aligning with Dannan and Dagda", says what each step did and what it cost in tests). The stack, its seams and the maintainer's rules are in `../dagda/TODO/2026-11-03-stack.md`; Lugh must not duplicate Dannan or Dagda, and the three share one style, convention and layout. Done so far: the header and layout; Dannan's SHA-256, compare, hex, Argon2id, signing, time sources, secure memory, codec, HKDF, AES-GCM, `Secret`, randomness, logging (text and JSON sinks), checked locks and test temp directories; HMAC-SHA-1 kept inside TOTP. Dannan is pinned by commit (`LUGH_DANNAN_COMMIT`), as no tag carries its Context yet.

Not next: the keyring's root from Dannan's key custody. The sealed store and `keys/` are frozen until Dagda carries Lugh's spaces and are deleted then (the maintainer: "Keep the store until Dagda"; the stack document's table), when Lugh's keys come from Dagda's domains under Dannan's custody through the Context (`derive_local`, `derive_key`). Rewiring them now would be work on code that is going. Until then they are changed only as far as the rest of the alignment needs.

Next, in order:
1. Callback style throughout (the maintainer: "Lugh goes callback style"): Dannan's shape, one shared state per operation on a strand, the deadline and the caller's executor, completion posted there and never inline. `Task<T>`, `offload` and `AsyncMutex` go.
2. Conventions: Dannan's warning set (`-Wshadow -Wconversion`); throwing instead of `Result` where Dannan's error rule says so; sanitizers before a release only; presets as the maintainer decides for all three.
3. `docs/architecture.md` rewritten around the stack: what Lugh is (the directory and its sign-in) on top of Dannan (network, identity, crypto) and Dagda (the store).

Not yet tried on Linux: `LoadCredentialEncrypted=`, `LimitMEMLOCK` and `MADV_DONTDUMP` are written for Ubuntu 26.04's systemd and kernel, and only the macOS paths have run. Check them on the first node.

## Waiting on the maintainer

- The open questions in `docs/architecture.md`, "Still open". Question 1 (node identity) is now Dannan's node identity; question 2 (single-use grants) is needed by P6 and P8; question 14 (Lugh's hostname) by P13.
- Durability of Lugh's writes on Dagda (Dagda's requirements document, section 8 item 1). The maintainer has decided every Dagda write carries a level the caller picks: Ephemeral, Persisted (one node) or Durable (every node of the replication set). Proposed for Lugh: Durable for credential and factor changes, revocations, disables, groups, memberships, policies and the audit chain; Persisted for node-local spaces (sessions, grants, TOTP steps); nothing Ephemeral. `lugh/scope` is every-node, so a Durable write with a node down waits for its deadline and comes back with evidence naming the pending node, though it has landed everywhere reachable. Proposed: Lugh answers success, "applied, n nodes pending", and records the same in the audit log, clearing it when the write's ticket reports the last node; or the maintainer adds "k of N" for credential changes and revocations. Dagda's evidence names each node by Dannan node id with its state.
- From the stack document: single-node revocation, the node key custody standard, TOTP replay across nodes, the partition bound, uniqueness by name, the trust boundary, Lugh's message type block (proposed 2048-3071), and whether all three projects keep CMake presets.

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
| **P8** | The cluster, on the stack. Lugh hosts on Dannan (`dannan::Context`: membership, mTLS transport, node identity, routes for Lugh's message types) and keeps its state in Dagda (head spaces `lugh/scope` and `lugh/secrets`, node-local spaces for sessions, grants and TOTP steps), replacing the interim sealed store and keyring; what the stack document (`../dagda/TODO/2026-11-03-stack.md`) sets out, and the multi-node tests. Lugh's own copy of Macha's membership and merge is not built |
| **P9** | LDAP. The BER decoder (fuzzed), LDAPS and StartTLS, bind, search with limits, rootDSE, the generated tree |
| **P10** | C++ library. `lugh_client` with public headers in `include/lugh/` and a CMake package config; `lugh::client::RelyingParty` (code flow, callback, ID token and back-channel logout verification); offline access token verification; client credentials and device flows; an example subproject |
| **P11** | WebAuthn and passkeys, the `phr` level, and app passwords for LDAP |
| **P12** | Hardening pass. Fuzzing campaigns, a review of the systemd sandbox, key rotation drills, a threat model document, an external review checklist |
| **P13** | SSO rollout, each in its own repository: blackraven-admin first (it is the smallest, and needs a `service` caller kind), then T.O.M.S (`IAuthProvider` redirect plus the `hub` service account), AthenaSIP admin, and Macha (a `CredentialValidator`, provisioning by `sub`, the device grant for the TV app). Each keeps a break-glass local account |
