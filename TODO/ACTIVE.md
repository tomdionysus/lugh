# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here

2026-11-05: **P6 and LDAP are done** on `develop`: OAuth and OIDC (`docs/oauth.md`, plan `2026-11-04-oauth.md`) and writable LDAP (`docs/ldap.md`, plan `2026-11-04-ldap.md`), each passing on the real binary. Next is P8 (hosting on Dannan's Context and Dagda), which waits on Dagda's heads. `lugh_tests` count and their history are in `COMPLETED.md`. Tests are run repeated and shuffled in the debug, ASan and TSan builds before a commit (the maintainer, 2026-11-04: "No flaky tests"). Commits since `0.1.0` are on `develop` and not pushed.

For the maintainer to confirm, none blocking: a session's scopes are read again within a minute rather than at once; CSRF only on requests that may change something; role mapping in the ID token and userinfo, not access tokens; an application with no audiences gets its `client_id` as `aud`; mTLS on its own optional listener (`oauth.mtls_port`); back-channel logouts waiting and what stands behind an opaque access token are in memory, so a restart forgets them; leaving Lugh after a form goes by a page rather than a 303, not yet tried in a real browser; everyone bound may search from LDAP's fixed containers; a person whose policy is `pwd` binds with their main password even with a factor enrolled. The LDAP fuzz targets have only been syntax-checked, since this machine has no libFuzzer.

Earlier, the alignment: **The alignment with Dannan and Dagda is done**, merged into `develop` and tagged `0.1.0` (`develop` and the tag pushed; `main` not, see "Not merged yet" below) (COMPLETED.md, "Aligning with Dannan and Dagda", says what each step did and what it cost in tests). Lugh links Dannan for every shared primitive and has no copy of one; it is in Dannan's callback shape above the frozen store and keyring; it has the stack's layout, conventions and warning set, with presets and routine sanitizers as its two stated exceptions; it has no Python; `docs/architecture.md` describes it as the top of the stack. `lugh_tests` (353) and `ctest` pass in the debug, ASan and TSan builds. Dannan is pinned by `LUGH_DANNAN_REF` to its tag 0.4.1.

**P6 was next** (the maintainer, 2026-11-04): OAuth 2 and OIDC, on the frozen store, in callback style, with the LDAP plan's L1 (the name fields) and L2 (app passwords with a scope set) folded into its start. Its design and steps O1 to O10 are `2026-11-04-oauth.md`, every question in it decided 2026-11-04; O1 (the fields) then O2 (the scope model that Lir and LDAP wait on) are first. Then LDAP, L3 to L5 (`2026-11-04-ldap.md`), then P8 (hosting on Dannan's Context and Dagda), which waits on Dagda's heads. P6 also defines the scope grammar Lir waits on ("For P6, from Lir").

Not next: the keyring's root from Dannan's key custody. The sealed store and `keys/` are frozen until Dagda carries Lugh's spaces and are deleted then (the maintainer: "Keep the store until Dagda"; the stack document's table), when Lugh's keys come from Dagda's domains under Dannan's custody through the Context (`derive_local`, `derive_key`). Rewiring them now would be work on code that is going. Until then they are changed only as far as the rest of the alignment needs.

What was next, in order:
1. Callback style: done above the frozen layers (COMPLETED.md has each step). Left as coroutines until Dagda, by the maintainer's decision: the sealed store, keyring, `Files` and `Console`, and the node's start-up (`tools/lugh_node.cpp`), which runs those in sequence and reaches the converted layers through `awaited`. `lugh/core/awaited.h`, `Task`, `offload`, `AsyncMutex` and `run()` go with them.
2. Errors: in the callback shape the answer posted to `done` carries the refusal or failure (an `Outcome`, a `Status`, a `Step`), as Dannan's `Done` carries its outcome; nothing throws across a callback. Left to decide: whether Lugh's remaining synchronous `Result` returns (the config loader, the TLS context, the record codecs' `std::optional`) should throw instead, per `CONTRIBUTING.md`. Small, and not urgent.
3. `docs/architecture.md` rewritten around the stack.

Not yet tried on Linux: `LoadCredentialEncrypted=`, `LimitMEMLOCK` and `MADV_DONTDUMP` are written for Ubuntu 26.04's systemd and kernel, and only the macOS paths have run. Check them on the first node.

## Not merged yet: Alpine and OpenRC (origin/main aaac977)

GitHub's `main` carries one commit this tree was never based on: aaac977 "Update" (the maintainer, 2026-10-29), Lugh building under Alpine (musl, GCC 15) for Raven, the maintainer's planned Alpine distribution, which every project of the stack will run under. It adds `deploy/openrc/` (the init script, its conf.d, and `lugh-master-key`, sealing the master key under the arm64 build node's OTP device key in place of `systemd-creds`), `GNUInstallDirs` so a package at `/usr` reads `/etc/lugh`, `deploy/lugh.service.in`, `LUGH_INSTALL_SYSTEMD` and `LUGH_INSTALL_OPENRC`, the installed config path in the version header, three GCC 15 `co_await` workarounds (no longer applicable above the frozen layers) and four test tweaks. It is on the old `src/` layout; a trial merge gave ten conflicts, mostly docs, CMake and the deleted coroutine files. The maintainer, 2026-11-04: real, leave it there, not important now. So local `main` (the 0.1.0 tag, pushed) is not pushed, since it would not fast-forward; when the time comes, merge `origin/main` into `develop` on the new layout, test in all three trees, fast-forward `main`, push.

## The stack serving Lugh (2026-11-13)

The maintainer, 2026-11-13: Dannan and Dagda must support Macha, Lugh and Lir as first-class citizens, "the purpose of splitting out the technologies". Lugh's needs, each with what was found in the other trees and what would show it, are `2026-11-13-lugh-needs-of-the-stack.md`, sent to the Dagda and Dannan sessions (Lir and Macha copied). Waiting on their answers: Dagda's plan and dates for the items not built (G2, G4 to G12, G14), and Dannan's answers to N1, N6, N8 and Alpine.

## Waiting on the maintainer

- The open questions in `docs/architecture.md`, "Still open": question 2 (single-use grants) is needed by P6 and P8, question 14 (Lugh's hostname) by P13.
- Nothing from the LDAP plan: its questions and review were decided 2026-11-04 (`2026-11-04-ldap.md`, "Decided").
- Nothing from the P6 plan: its questions were decided 2026-11-04 (`2026-11-04-oauth.md`, "Decided").

## For P8, from Dannan

Dannan's identity step (step 10, Dannan 09a525f, design in `../dannan/TODO/2026-11-04-identity.md`) gives what Lugh fills when it hosts on Dannan: the scope seam, `dannan/contract/scope.h` (`contract::Principal`, `contract::ScopeDecision`, and `ScopeSource::may_write(principal, prefix)`, answered from memory and never waiting), installed with `context.identity().install_scope_source(...)`; without a source the cluster's own nodes may write and nobody else. Single-node revocation is CA-signed, kept by every node and gossiped, closing the revoked node's sessions at once. Node keys live in Dannan's key custody, like Lugh's master key. Not tagged; whether to cut 0.3.0 is the maintainer's.

## For P10, from Lir (2026-11-13)

Lir's plugin sees only its `TokenVerifier` seam (`lir/auth/tokens.h`); `lugh_client` is to be that verifier, and Lir parses no JOSE and fetches no keys. Lir asks two things of `lugh_client`, agreed: keep where the signing keys come from behind it (retained values in `lugh/scope` once Dagda has them, HTTPS JWKS until then); and keep HTTPS working for a node whose cluster has no Lugh node or is not a member of `lugh/scope`, since Lir must also serve as an ordinary relying party.

## For P6, from Lir

The maintainer decided Lir's authorisation (2026-11-04, via the Lir session): MQTT topic permissions are scopes carried in the Lugh token, publish and subscribe topic filters, checked through Dannan's scope check; Lir keeps no ACL. A client presents the token as the MQTT CONNECT password, and an MQTT 5 client may re-authenticate with the enhanced authentication method "lugh". The grammar of those scopes is Lugh's to define, in P6 with the rest of the scope model (group-to-scope grants, app-defined scopes), and Lir waits on it. Also from the maintainer, via Lir: the repositories are the sources of truth; the Claude Docs the projects started from are starters only and will be deleted, not read for direction or edited.

## Onto Dannan's new foundations (rule 3): done 2026-11-04

Dannan 0.4.0 (main d657a9b) held two things Lugh had copies of, and Lugh now uses both: the settings reader (`dannan/config/config.h`, lifted from Lugh's `ConfigLoader`), with Lugh declaring its settings and keeping its typed `Config` and its own checks, and percent-encoding (below). Lugh's `system::Environment` port, an exact copy of Dannan's, went with the reader. COMPLETED.md has what changed and why the test count fell.

## Percent-encoding moved to Dannan (done 2026-11-04)

The maintainer (2026-11-04, via Lir): percent-encoding is a Dannan foundation that every project uses (`dannan/encoding/percent.h`, in 0.4.0). Lugh's topic scopes encode and decode with it, and the router decodes with it: path parameters strictly (`+` literal, RFC 3986), queries as forms (`+` a space), and a malformed escape (`%zz`, a trailing `%`) answered 400 rather than passed through, which is what the old `Router::percent_decode` did. That function is gone.

## For P8, from Dagda

Dagda (2026-11-04, on Dannan 0.3.0, its step 6) gives the write shape Lugh will see: every Dagda write takes `WriteOptions` with a durability level, a principal (`dannan::contract::Principal`, default the writing node) and a prefix (default the domain's name), and every storing replica calls `Identity::verify(principal, prefix)` before storing, refusing with evidence per node. So the `ScopeSource` Lugh installs through `Identity::install_scope_source` is what decides a directory principal's write to `lugh/scope` and `lugh/secrets`. Node-local domains are under the node's custody (`derive_local`), domain keys are wrapped to members over per-node X25519 wrap keys, and the domain is bound into the AEAD associated data. The domain catalogue, node-local spaces, per-space k and retained values come with Dagda's heads (its step 4), which wait on Macha's tree-native merge; P8 waits on those.

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
- **Dannan 0.2.0** is a tag with install and export targets (`find_package(dannan 0.2 CONFIG)`, `dannan::dannan`); Lugh pins a tag. Now 0.3.0 (Dannan main 277adab: identity with CA-signed revocation and the scope seam, `contract::Unlocked`, cancelled late `Routes::call`s, `context.time().source()` and `executor()`, `sched::DutyShare`, `NodeEvents::membership`, `Nodes::absent_since`).

## Plan

Each phase ends with a green build, `ctest` passing under the `debug` and `asan` presets, the fuzz targets building, and a commit.

| ID | Phase |
|---|---|
| **P1** | Skeleton. CMake with presets (`debug`, `release`, `asan`, `tsan`, `fuzz`) and hardening flags; `lugh_core`, `lugh` and the tests; `.clang-format`; the config layering; the logger with secret redaction; `system/` ports; the IoC check; the HTTPS server (TLS 1.3) with `/health`; the shutdown test; the systemd unit and host setup; `docs/code-style.md` |
| **P2** | Crypto and keys. A `crypto/` layer over OpenSSL 3 (AEAD, HKDF, Argon2id, Ed25519/ES256, constant-time compare, secure memory), the key hierarchy, unsealing the master key from a systemd credential, `lugh init` |
| **P3** | The store, on one node. Copy `SealedJournal`, `LocalStore` and the ledger from Macha, strip the licence headers and adapt them to the conventions; sealed records with associated data; tables and derived indexes; compaction with DEK re-sealing; crash and torn-write tests |
| **P4** | Directory and authentication. Users, groups, memberships; Argon2id passwords; lockout and back-off; TOTP with replay refusal; recovery codes; enrolment links and forced enrolment; the audit log with its hash chain |
| **P5** | Management API. `/api/v1` CRUD, scoped permissions, ETags and the error format. Genesis: root and its one-time password, the only credential. The API opens to sessions and tokens in P6 |
| **P6** | OAuth 2 and OIDC: the design and steps O1 to O10 are `2026-11-04-oauth.md`, with the scope model (and Lir's topic-scope grammar), sessions, the sign-in pages, grants, tokens, the endpoints, and the API opening to callers; L1 and L2 of the LDAP plan folded in. As first planned: Applications (`apps`, `app_access`, role mapping, `private_key_jwt`, exact redirect matching); the SSO session; `acr`/`amr`, `max_age` and step-up; RP-initiated and back-channel logout; authorisation code with PKCE, client credentials, refresh rotation, the sign-in and consent pages, JWT access and ID tokens, JWKS and discovery, introspection, revocation, PAR, DPoP, the device grant. The API then switches to OAuth tokens |
| **P7** | Dashboard. The React SPA in T.O.M.S's styling, using the Lugh session cookie and a CSRF token against `/api/v1`, served from disk by the static handler, with a strict CSP; installed by `cmake --install` |
| **P8** | The cluster, on the stack. Lugh hosts on Dannan (`dannan::Context`: membership, mTLS transport, node identity, routes for Lugh's message types) and keeps its state in Dagda (head spaces `lugh/scope` and `lugh/secrets`, node-local spaces for sessions, grants and TOTP steps), replacing the interim sealed store and keyring; what the stack document (`../dagda/TODO/2026-11-03-stack.md`) sets out, and the multi-node tests. Lugh's own copy of Macha's membership and merge is not built |
| **P9** | LDAP, writable, as a second front end on `Directory` (the maintainer, 2026-11-04, "level 2"): steps L1 to L5 in `2026-11-04-ldap.md`. The BER decoder (fuzzed), LDAPS and StartTLS, bind, search with limits and paging, compare, the generated tree, then add, modify, delete, rename, the Assertion control and Password Modify. Takes app passwords from P11 |
| **P10** | C++ library. `lugh_client` with public headers in `include/lugh/` and a CMake package config; `lugh::client::RelyingParty` (code flow, callback, ID token and back-channel logout verification); offline access token verification; client credentials and device flows; an example subproject |
| **P11** | WebAuthn and passkeys and the `phr` level (app passwords moved to P9's L2) |
| **P12** | Hardening pass. Fuzzing campaigns, a review of the systemd sandbox, key rotation drills, a threat model document, an external review checklist |
| **P13** | SSO rollout, each in its own repository: blackraven-admin first (it is the smallest, and needs a `service` caller kind), then T.O.M.S (`IAuthProvider` redirect plus the `hub` service account), AthenaSIP admin, and Macha (a `CredentialValidator`, provisioning by `sub`, the device grant for the TV app). Each keeps a break-glass local account |
