# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here (2026-11-14)

P6 (OAuth and OIDC) and P9 (writable LDAP) are done; P8 is planned and its first steps wait on Dagda. The Linux pass is green and committed (2026-11-14): debug, ASan with leak detection and TSan, 666 tests each, on the build nodes. The maintainer, 2026-11-14: **no builds or tests on the Mac**, only on the build node cluster (below).

**Lugh is paused** (the maintainer, 2026-11-14, after P10): nothing is taken up until the maintainer says, or until P8 or the move to Dannan 0.8.0 is unblocked (below).

Lugh is on Dannan 0.7.0. **P10, `lugh_client`, is done** (2026-11-14; `COMPLETED.md`): 724 tests, green in debug, ASan with leaks and TSan on the build nodes; on `develop` at dbb0573, pushed. Lir's Lugh plugin is repinned there (Lir 33b7c8b, 343 tests on a build node, nothing internal of Lugh's included) and repins next at Lugh's first release. `docs/client.md` describes the library.

Waiting, so not next: P8 (Dagda paused for Macha's port, the maintainer 2026-11-14; 0.2.0 tagged locally, unpushed), P8.5 also on the follower-lag fix (Dagda slice 2), and the move to Dannan 0.8.0 (the maintainer holds it until Dannan's P5 benchmarks; then set `DANNAN_BUILD_TOOLS` OFF where Lugh fetches Dannan, build the hashing pool on `sched::WorkerPool`, and move HTTPS, mTLS and LDAP onto `dannan::listen`, whose close cancels a pending read with operation_aborted). Next is the maintainer's choice among P7 (dashboard), P11 (WebAuthn) and P12 (hardening; the fuzz targets, never yet built, can be on node-a's clang 19, and `lugh/fuzz/client_fuzz.cpp` is written for lugh_client's readers, uncommitted until it builds there).

The installed package config (`find_package(lugh)`) waits for a release, since Lir fetches. Sync to the build nodes with `rsync -rlpgoD`, not `-a`. node-a is the stack's TSan build node (clang 19, 4K pages; `config.txt.pre-4k` restores the 16K kernel), Lugh's TSan tree `~/lugh/build-tsan`; node-b keeps `~/lugh/build` and `~/lugh/build-asan` (GCC 14); node-d has `~/lugh/build` (debug, 4 GB, 16K pages).

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
| P10 | `lugh_client`, the C++ library (`2026-11-14-p10-plan.md`, `docs/client.md`) | done |
| P11 | WebAuthn, passkeys and the `phr` level | not started |
| P12 | Hardening: fuzzing campaigns, sandbox review, key rotation drills, threat model | not started |
| P13 | SSO rollout: blackraven-admin, T.O.M.S, AthenaSIP admin, Macha; one break-glass account each | not started |
