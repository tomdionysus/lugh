# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here

2026-11-04: **Aligning with Dannan and Dagda** on `feature/dannan-alignment`, one commit per step, nothing pushed (COMPLETED.md, "Aligning with Dannan and Dagda", says what each step did and what it cost in tests). The stack, its seams and the maintainer's rules are in `../dagda/TODO/2026-11-03-stack.md`; Lugh must not duplicate Dannan or Dagda, and the three share one style, convention and layout. Done so far: the header and layout; Dannan's SHA-256, compare, hex, Argon2id, signing, time sources, secure memory, codec, HKDF, AES-GCM, `Secret`, randomness, logging (text and JSON sinks), checked locks and test temp directories; HMAC-SHA-1 kept inside TOTP. Dannan is pinned by `LUGH_DANNAN_REF` to ca029bb, its 0.2.0 release with the `ChildProcess` options the process tests use; move it to the next tag when Dannan cuts one. Linked as `dannan::dannan`.

Not next: the keyring's root from Dannan's key custody. The sealed store and `keys/` are frozen until Dagda carries Lugh's spaces and are deleted then (the maintainer: "Keep the store until Dagda"; the stack document's table), when Lugh's keys come from Dagda's domains under Dannan's custody through the Context (`derive_local`, `derive_key`). Rewiring them now would be work on code that is going. Until then they are changed only as far as the rest of the alignment needs.

Next, in order:
1. Callback style (the maintainer: "Lugh goes callback style"; Dannan's shape) for the directory, authn, API, HTTP and node layers. The frozen sealed store, keyring, `Files` and `Console` keep their coroutines until Dagda replaces them (the maintainer, 2026-11-04). The design, layer by layer, each a green commit:
   - **Shape.** Every operation is `op(arguments..., Deadline, Executor, Done<T>)`: `done` posted to the caller's executor exactly once, with the answer or, when the deadline passes first, what the operation says then; never inline; the call itself waits on nothing. `lugh/core/completion.h` (`Completion<T>`, `answer_now`) is the one place that keeps that promise, tested under TSan. Done.
   - **Deadlines on local work.** A write whose deadline passes is answered `failed`, saying it may yet land, as Dagda's ticket will say for a replicated one; a read is answered `failed`, never "not found", so a timeout is not mistaken for absence.
   - **Composition.** An operation of several steps keeps one shared state (its `Completion`, its inputs, what each step learned); each step's handler starts the next, and the last calls `finish`. Dannan's `net/client.cpp` (`Client::dial`) is the model. A sequence that must not interleave (the audit chain's next number) is a queue on the component, one in flight, not a lock across steps.
   - **The frozen store from above.** `lugh/store/store_calls.h`: the store's operations in this shape, each spawning the store's coroutine and finishing a `Completion` with its answer, its exception as `failed`, or the deadline.
   - **While both styles live.** Bottom up: the audit log, then the directory, then passwords, factors, enrolment links, policy and genesis, then the authenticator, then the routes and router, then the node. A layer not yet converted calls a converted one through a temporary `Task` bridge (`async_initiate` over the callback), deleted with the last coroutine caller above the store. Tests wait on callbacks with a helper beside `run()`.
   - **Then** `Task`, `offload` and `AsyncMutex` are used only by the frozen store, keyring, files and console, and go with them.

2. Errors as `CONTRIBUTING.md` says (throw what could not happen), with the callback change.
3. `docs/architecture.md` rewritten around the stack.

Not yet tried on Linux: `LoadCredentialEncrypted=`, `LimitMEMLOCK` and `MADV_DONTDUMP` are written for Ubuntu 26.04's systemd and kernel, and only the macOS paths have run. Check them on the first node.

## Waiting on the maintainer

- The open questions in `docs/architecture.md`, "Still open": question 2 (single-use grants) is needed by P6 and P8, question 14 (Lugh's hostname) by P13.

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
| **P9** | LDAP. The BER decoder (fuzzed), LDAPS and StartTLS, bind, search with limits, rootDSE, the generated tree |
| **P10** | C++ library. `lugh_client` with public headers in `include/lugh/` and a CMake package config; `lugh::client::RelyingParty` (code flow, callback, ID token and back-channel logout verification); offline access token verification; client credentials and device flows; an example subproject |
| **P11** | WebAuthn and passkeys, the `phr` level, and app passwords for LDAP |
| **P12** | Hardening pass. Fuzzing campaigns, a review of the systemd sandbox, key rotation drills, a threat model document, an external review checklist |
| **P13** | SSO rollout, each in its own repository: blackraven-admin first (it is the smallest, and needs a `service` caller kind), then T.O.M.S (`IAuthProvider` redirect plus the `hub` service account), AthenaSIP admin, and Macha (a `CredentialValidator`, provisioning by `sub`, the device grant for the TV app). Each keeps a break-glass local account |
