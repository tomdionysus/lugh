# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here

2026-11-04: **The alignment with Dannan and Dagda is done** on `feature/dannan-alignment`, one commit per step, nothing pushed, not yet merged into `develop` (COMPLETED.md, "Aligning with Dannan and Dagda", says what each step did and what it cost in tests). Lugh links Dannan for every shared primitive and has no copy of one; it is in Dannan's callback shape above the frozen store and keyring; it has the stack's layout, conventions and warning set, with presets and routine sanitizers as its two stated exceptions; it has no Python; `docs/architecture.md` describes it as the top of the stack. `lugh_tests` (353) and `ctest` pass in the debug, ASan and TSan builds. Dannan is pinned by `LUGH_DANNAN_REF` to ca029bb (0.2.0 with the ChildProcess options) until its next tag.

Next is the maintainer's call: merge this branch into `develop`; then P6 (OAuth 2 and OIDC, on the frozen store, in callback style) or P8 (hosting on Dannan's Context and Dagda, once Dagda carries Lugh's spaces).

Not next: the keyring's root from Dannan's key custody. The sealed store and `keys/` are frozen until Dagda carries Lugh's spaces and are deleted then (the maintainer: "Keep the store until Dagda"; the stack document's table), when Lugh's keys come from Dagda's domains under Dannan's custody through the Context (`derive_local`, `derive_key`). Rewiring them now would be work on code that is going. Until then they are changed only as far as the rest of the alignment needs.

What was next, in order:
1. Callback style: done above the frozen layers (COMPLETED.md has each step). Left as coroutines until Dagda, by the maintainer's decision: the sealed store, keyring, `Files` and `Console`, and the node's start-up (`tools/lugh_node.cpp`), which runs those in sequence and reaches the converted layers through `awaited`. `lugh/core/awaited.h`, `Task`, `offload`, `AsyncMutex` and `run()` go with them.
2. Errors: in the callback shape the answer posted to `done` carries the refusal or failure (an `Outcome`, a `Status`, a `Step`), as Dannan's `Done` carries its outcome; nothing throws across a callback. Left to decide: whether Lugh's remaining synchronous `Result` returns (the config loader, the TLS context, the record codecs' `std::optional`) should throw instead, per `CONTRIBUTING.md`. Small, and not urgent.
3. `docs/architecture.md` rewritten around the stack.

Not yet tried on Linux: `LoadCredentialEncrypted=`, `LimitMEMLOCK` and `MADV_DONTDUMP` are written for Ubuntu 26.04's systemd and kernel, and only the macOS paths have run. Check them on the first node.

## Waiting on the maintainer

- The open questions in `docs/architecture.md`, "Still open": question 2 (single-use grants) is needed by P6 and P8, question 14 (Lugh's hostname) by P13.
- The LDAP plan's six questions, `2026-11-04-ldap.md` "For the maintainer": the name fields on `User`, TLS 1.3 only, app passwords brought forward, `ou=services`, `ldap.base_dn`, and where L1 to L5 go relative to P6 and P8.

## For P8, from Dannan

Dannan's identity step (step 10, Dannan 09a525f, design in `../dannan/TODO/2026-11-04-identity.md`) gives what Lugh fills when it hosts on Dannan: the scope seam, `dannan/contract/scope.h` (`contract::Principal`, `contract::ScopeDecision`, and `ScopeSource::may_write(principal, prefix)`, answered from memory and never waiting), installed with `context.identity().install_scope_source(...)`; without a source the cluster's own nodes may write and nobody else. Single-node revocation is CA-signed, kept by every node and gossiped, closing the revoked node's sessions at once. Node keys live in Dannan's key custody, like Lugh's master key. Not tagged; whether to cut 0.3.0 is the maintainer's.

## Decided (the maintainer, 2026-11-04)

From this session and the stack document's "Decided" section (`../dagda/TODO/2026-11-03-stack.md`):

- **Callback style** leaves the frozen store, keyring, files and console code alone, behind an adapter, until Dagda.
- **Durability on Dagda**: four levels, Ephemeral, Persisted (one node), Replicated (k nodes, k per space, default 2) and Durable (every available replica, dead nodes skipped). Credential and factor changes and revocations are Replicated. Where a write leaves nodes pending, Lugh answers success, "applied, n nodes pending", records the same in the audit log, and clears it when the write's ticket reports the last node.
- **Presets**: Lugh keeps its CMake presets, the stack's one exception, "because of auth".
- **Sanitizers** run routinely in Lugh (ASan with UBSan, and TSan, at the end of every phase), its exception to the stack's before-a-release rule.
- **No Python** in any project; process tests are GoogleTest.
- **Sessions are replicated** across Lugh nodes, with `lugh/secrets` (Lugh nodes only), so a session works at any Lugh node; the space is Lugh's design. Single-use grants and TOTP steps stay node-local or a lease.
- **Lugh's domains**: `lugh/scope` (every node a member) and `lugh/secrets` (Lugh nodes). Merge keeps tombstones forever; ETags are Lugh's version checked inside Dagda's `mutate_local`.
- **The scope seam is Dannan's**: Dannan declares `contract::ScopeSource` and `Identity::verify`, and Lugh installs the source.
- **Message types**: Dannan's core types are 1 to 511; Lugh registers its own from 512, with no per-project block.
- **One process per node**: `lugh-node` is a Dannan node, as its own user. Node revocation is CA-signed, in Dannan's step 10.
- **HTTP stays Lugh's**; token verification does not move to Dannan; Lir's authentication is pluggable, and a Lugh plugin there depends on Lugh.
- **Accepted limits**: the partition bound and the trust boundary.
- **Dannan 0.2.0** is a tag with install and export targets (`find_package(dannan 0.2 CONFIG)`, `dannan::dannan`); Lugh pins it.

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
| **P9** | LDAP, writable, as a second front end on `Directory` (the maintainer, 2026-11-04, "level 2"): steps L1 to L5 in `2026-11-04-ldap.md`. The BER decoder (fuzzed), LDAPS and StartTLS, bind, search with limits and paging, compare, the generated tree, then add, modify, delete, rename, the Assertion control and Password Modify. Takes app passwords from P11 |
| **P10** | C++ library. `lugh_client` with public headers in `include/lugh/` and a CMake package config; `lugh::client::RelyingParty` (code flow, callback, ID token and back-channel logout verification); offline access token verification; client credentials and device flows; an example subproject |
| **P11** | WebAuthn and passkeys and the `phr` level (app passwords moved to P9's L2) |
| **P12** | Hardening pass. Fuzzing campaigns, a review of the systemd sandbox, key rotation drills, a threat model document, an external review checklist |
| **P13** | SSO rollout, each in its own repository: blackraven-admin first (it is the smallest, and needs a `service` caller kind), then T.O.M.S (`IAuthProvider` redirect plus the `hub` service account), AthenaSIP admin, and Macha (a `CredentialValidator`, provisioning by `sub`, the device grant for the TV app). Each keeps a break-glass local account |
