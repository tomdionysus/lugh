# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here (2026-11-14)

P6 (OAuth and OIDC) and P9 (writable LDAP) are done; P8 is planned and its first steps wait on Dagda. The Linux pass is green and committed (2026-11-14): debug, ASan with leak detection and TSan, 666 tests each, on the build nodes. The maintainer, 2026-11-14: **no builds or tests on the Mac**, only on the build node cluster (below).

Lugh is on Dannan 0.7.0 (2026-11-14); `develop` pushed at `7b0c717`. Now: **P10, `lugh_client`** (the maintainer, 2026-11-14: the work while Dagda's slice 1 is awaited), planned in `2026-11-14-p10-plan.md` with the maintainer's rulings (links Dannan; knows nothing of Lir, whose optional Lugh plugin adapts it; Lir pins a `develop` commit; all of P10 as one phase). Work is on `feature/lugh-client`. P10.0 so far (2026-11-14): `jose` moved to `lugh/client/` as `lugh::client`, Boost.JSON's definitions moved there, and the `lugh_client` static library (`lugh::client`) built, linked by the node's `lugh`; `LUGH_BUILD_NODE=OFF` builds it alone (tried on node-b); Lugh fetches Dannan only when no `dannan::dannan` exists. The access-token checks are the library's (`lugh::client::check_access_token`), `TokenIssuer::verify` calling them. P10.0 done: 674 tests (8 new), debug on a build node. P10.1 and P10.2 done (2026-11-14): the public `Verifier`, `Https` and `HttpsKeySource`, 693 tests, the new threaded and timing tests repeated in debug, ASan and TSan. P10.3a done (2026-11-14): `lugh::client::OAuthClient` (code with PKCE and PAR, the return checked, the ID token verified, refresh, client credentials; public, `private_key_jwt` or `client_secret_basic`), 704 tests. P10.3b done: the device flow (RFC 8628), 708 tests, its polling tests repeated in debug, ASan and TSan. P10.3c done: DPoP proofs (no nonce: Lugh asks for none), 712 tests. The maintainer, 2026-11-14: merged into `develop` now (fast-forward to 2b60b52, pushed with `feature/lugh-client`), named to Lir to pin. Dagda's 0.2.0 is tagged locally and not pushed: the maintainer ruled later the same evening (to Dagda) that Macha's port to Dagda comes first, and all Dagda slice work, the follower-lag fix (slice 2) included, waits until Macha runs on Dagda as well as on its own store. So P8 has no tag to start on; Lugh stays on P10. Lir's Lugh plugin is merged on Lir's develop (9452fd0), pinned at 2b60b52, both link configurations green on a build node; Lir repins when P10 is done (told), and its tests use the internal `lugh/client/jose.h` (offered a public test-support header if it wants one). When Lugh moves to Dannan 0.8.0's listener: a close cancels a pending read with operation_aborted, which Lugh's readers treat as the end. Written, not yet built: P10.3d (`tls_client_auth`, `HttpsClient` client certificates, the mTLS aliases), P10.4 (introspection, revocation), P10.5 (`ApiClient`, `Https` with PATCH, PUT, DELETE and ETags, the shared `RecordingHttps` fixture); about 722 tests expected. Next: P10.3d, `tls_client_auth` (a client certificate and key in `HttpsClient`, requests to the discovery document's `mtls_endpoint_aliases`), then P10.4 (introspection, revocation). Sync to the build nodes with `rsync -rlpgoD`, not `-a` (memory, pi-build-servers). The installed package config (`find_package(lugh)`) waits for a release, since Lir fetches. When Lugh moves to Dannan 0.8.0, set `DANNAN_BUILD_TOOLS` OFF where it fetches Dannan. ASan and TSan run at P10's end. P8.0 to P8.4 start on slice 1's tag (`2026-11-13-p8-plan.md`). node-a is the stack's TSan build node (clang 19, 4K pages; `config.txt.pre-4k` restores the 16K kernel); Lugh's TSan tree is `~/lugh/build-tsan` there, built with `clang++-19`; node-b keeps `~/lugh/build` and `~/lugh/build-asan` (GCC 14).

## The build node cluster

node-a `.11`, node-b `.12`, node-c `.13` (Debian 13 arm64, GCC 14, Boost 1.83), shared by every session. Lugh's things are under `/srv/build/lugh`. Claim a machine on Lir's board before heavy work (first come, first served, one heavy job per build node, release at once, `until` honest); the claim-board plugin's tools (`claim_take`, `claims_list`, `note_post`, ...) replace curl after a session restart. `nice 19`, `-j2`. Post a note before a reboot. Not node-c for reboots (LED Config's services). Recipes: `../lir/deploy/pi-cluster/README.md`.

## Waiting

- **Dagda's slice 1 tag** (0.2.0, local, unpushed; Dagda paused for Macha's port, the maintainer 2026-11-14): P8.0 to P8.4 start on it (`2026-11-13-p8-plan.md`). Slice 1 is merged on Dagda's `develop` (1065b18, 2026-11-14, proven on a build node), not yet tagged or pushed: the tag (Dagda recommends 0.2.0) and the push are the maintainer's. It gives the installed fixture (`dagda::test_fixtures`, header-only, `dagda/test/fixtures/cluster.h`; link GTest, set `DANNAN_TEST_TEMP_ROOT`); the change notice (`Heads::watch(space, executor, notice)`, posted on every move of the head, a peer's commit included, as `HeadMoved{before, after}`; `Heads::changed(...)` pages the differing keys; read a space once before watching it, or the first notice carries the founding's keys); node-local spaces (`Policy::node_local()`, durable before a commit returns; no DATA object yet; no-rollback refuses a space directory restored alone, not a whole state restored together). Build against contract v2, pinned to the slice tag.
- **Dannan 0.7.0 is tagged** (2026-11-14; `Nodes::partition()`, `watch_partition`, against `members()` and `retire()`; SONAME `libdannan.so.0.7`; .debs wait on the maintainer's publish). Lugh is pinned to it; the partition in Status and the audit log lands with P8.1, when `lugh-node` becomes a Dannan node.
- **Dagda slice 2, follower lag on the build node**: on node-a a second node saw Lugh-shaped commits at p50 10 s, p99 22 s and growing (Mac: 103 ms); P8.5 does not land until a follower keeps up at Lugh's rates on a build node, a disable seen elsewhere within about a second (the maintainer ruled, 2026-11-14; `2026-11-13-lugh-needs-of-the-stack.md`, "The build node").
- **The maintainer, at P13**: `docs/architecture.md` question 10 (TLS for T.O.M.S sites, or sign-in only at the hub). Questions 2 and 14 are settled there.
- **Not merged, by the maintainer's choice**: GitHub's `main` carries aaac977 (Alpine and OpenRC for Raven), never merged here; Raven is dropped for now (the maintainer, 2026-11-13). Local `main` (tag 0.1.0) is not pushed since it would not fast-forward. When Raven returns: merge `origin/main` into `develop` on the new layout (about ten conflicts), test, fast-forward `main`, push.
- **Not yet tried on Linux**: `LoadCredentialEncrypted=`, `LimitMEMLOCK` and `MADV_DONTDUMP` (written for systemd; only macOS paths have run). The LDAP and envelope fuzz targets are syntax-checked only (no libFuzzer on the Mac; clang 19 on node-a will have it).

## Documents

- `2026-11-13-p8-plan.md`: P8, the rewrite of each component against Dagda's spaces, steps P8.0 to P8.9, the maintainer's rulings. The merge it needs is built (`lugh/merge/record_merge.h`).
- `2026-11-13-lugh-needs-of-the-stack.md`: what Lugh needs of Dannan (N1 to N10) and Dagda (G1 to G15), their answers, the maintainer's rulings, slice 0's figures (about 85 to 90 head commits a second per node; Lugh's sign-in cut to two commits).
- `2026-11-04-oauth.md`, `2026-11-04-ldap.md`: the P6 and P9 plans, done; kept as the design record behind `docs/oauth.md` and `docs/ldap.md`.
- `../dagda/TODO/2026-11-03-stack.md`: what each project of the stack owns.

## Standing decisions

The ones that shape the next work; the rest are in the plans and `COMPLETED.md`.

- The sealed store, keyring, `Files`, `Console` and the node's start-up stay coroutines and frozen until Dagda carries Lugh's spaces, then are deleted ("Keep the store until Dagda"). Keys then come from Dagda's domains under Dannan's custody.
- Lugh's domains: `lugh/scope` (every node a member) and `lugh/secrets` (Lugh nodes, a configured-member domain). Credential and factor changes and revocations are Replicated; a write with nodes pending answers "applied, n nodes pending" and is audited. TOTP is a per-user Dagda lease, failing closed on the minority side; the minority side reports only.
- Lugh installs Dannan's `ScopeSource`; message types from 512; one `lugh-node` per node; HTTP stays Lugh's.
- For P10 (from Lir): `lugh_client` is Lir's `TokenVerifier`, keeps the source of signing keys behind it (retained values in `lugh/scope`, HTTPS JWKS until then), and keeps HTTPS working where the cluster has no Lugh node.
- Lir's MQTT permissions are Lugh scopes (topic filters), checked through Dannan; a client presents the token as the CONNECT password.
- Left to decide, small: whether Lugh's remaining synchronous `Result` returns (config loader, TLS context, record codecs) should throw, per `CONTRIBUTING.md`.

## Plan

Each phase ends green in the debug, ASan and TSan builds, one run each, and a commit. The maintainer, 2026-11-14 (relayed to every session): running the same tests more than once needs a reason, a flaky test or odd behaviour; new tests that touch threads or timing are repeated on their own with a filter, never the whole suite by default. ASan and TSan are for releases elsewhere in the stack; Lugh keeps them per phase.

| ID | Phase | State |
|---|---|---|
| P1 | Skeleton: CMake, presets, config, logger, IoC check, HTTPS, systemd unit | done |
| P2 | Crypto and keys over OpenSSL 3, the key hierarchy, `lugh init` | done |
| P3 | The sealed store, on one node | done, frozen until P8 |
| P4 | Directory and authentication: users, groups, Argon2id, back-off, TOTP, recovery codes, enrolment, the audit chain | done |
| P5 | Management API `/api/v1` | done |
| P6 | OAuth 2 and OIDC (`2026-11-04-oauth.md`, `docs/oauth.md`) | done |
| P7 | Dashboard: the React SPA in T.O.M.S's styling | not started |
| P8 | The cluster on the stack: Dannan's `Context`, Dagda's spaces, replacing the sealed store and keyring; multi-node tests (`2026-11-13-p8-plan.md`) | planned, waits on Dagda slice 1 |
| P9 | Writable LDAP (`2026-11-04-ldap.md`, `docs/ldap.md`) | done |
| P10 | `lugh_client`, the C++ library | not started |
| P11 | WebAuthn, passkeys and the `phr` level | not started |
| P12 | Hardening: fuzzing campaigns, sandbox review, key rotation drills, threat model | not started |
| P13 | SSO rollout: blackraven-admin, T.O.M.S, AthenaSIP admin, Macha; one break-glass account each | not started |
