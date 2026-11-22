# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here (2026-11-22)

**Releases.** 0.2.0 (packaged), 0.3.0 (Dannan 0.10.0) and 0.4.0 (the stack's config names, Dannan 0.10.2; source only)
are tagged on `main`; `CHANGELOG.md` says what each holds. The merged `feature/*` branches were deleted, locally and on
GitHub (the maintainer's word, 2026-11-22).

**After 0.4.0's tag:** tell the dependants (Louhi, Kvasir, Mimir, Lir's plugin) that the four flags were renamed.

**The Debian package:** none since 0.2.0. It waits for Dagda's release on Dannan 0.10.x in the apt repository, because
the package build runs the tests against Dagda's packages. Building it locally is fine; putting it in the apt repository
waits on the maintainer's word.

**After 0.4.0: onto the rest of Dannan 0.10.x** (from its release notes; one step each, as each changes behaviour or
public API):
1. **The callback vocabulary.** lugh_client's and the node's `Outcome`, `Fault` and `Completion` become Dannan's
   `contract/completion.h` (one Fault kind for the stack; `unavailable` and `timed_out` answer 503). This changes
   lugh_client's public types, so tell Louhi, Kvasir, Mimir and Lir first.
2. **The encodings.** `lugh/core/encoding.h` becomes `encoding/base.h`; its exact decoders write a secret straight
   into a `SecureBuffer`.
3. **TOTP's HMAC-SHA-1** becomes `identity::hmac_sha1`.
4. **Random IDs** become `identity::RandomId<Tag>`.
5. **`network::Cidr`** becomes `listen::Prefix`, which refuses host bits set past the length (`10.0.0.1/8` would then
   stop the start; say so in the release notes).
6. **The tests' `RecordingSink`** becomes `test::RecordingSink`, and lugh_node's late logger swap becomes
   `status::SwappableSink`.
7. Directories made and synced by hand use `identity::durable_create_directories` and `durable_sync_directory`.
8. The fuzz targets also run as smoke tests in `lugh_tests` through `dannan::testing`, so CI exercises each corpus.
Not taken: `agree::MemoryStore`, `each_held` and the agreement teardown fixes, which are P8's; the ack levels.

**Also waiting to be done, not blocked:**
- `@lugh/admin-ui`: the dashboard's shell carved into a package for Lir, Louhi, Mimir and Kvasir (`2026-11-20-dependants.md`,
  "The shared admin UI"). npm, tested in GitHub CI, so no cluster time. Whether the dashboard's 5 Playwright tests move
  into Vitest's browser mode is asked of the maintainer.
- Coverage: the rest of the gap, file by file (`COMPLETED.md`, "Coverage closer to whole", lists what is left and why).

**P8, the cluster on the stack** (`2026-11-13-p8-plan.md`). P8.0 is done. The rest waits on its dependencies, by the
no-duplication rule:
- P8.1 (lugh-node a Dannan node) waits on Dannan's node-program helper and founding act (Dannan's plan, items 4 and 14).
- P8.2 to P8.4 wait on Dagda's register map (D6), which replaces Lugh's own merge and codec.
- P8.5 waits on Dagda's slice 2; P8.6 on the durable AcceptorStore and Dannan's register layer; P8.7 on D9.

## Waiting on others

- **Dagda's register map, D6** (`../dagda/TODO/2026-11-20-register-map.md`). `lugh/scope` and `lugh/secrets` become
  register-map spaces, and `merge::winner` and `merge()` go (`UniqueIndex` stays). Lugh's review was taken whole
  (2026-11-20):
  - tombstone-wins with "never" (the maintainer's "removal over edit, never resurrected");
  - a put onto a tombstone refused, and `get_register` for a 410;
  - `changed()` answering each key's before and after, for the indexes;
  - a 64 KiB value bound refused at put. Lugh's own bound (`merge::kMostValueBytes`, 256 KiB) drops to 64 KiB at P8.3.
- **Dagda's caught-up signal** (`../dagda/TODO/2026-11-20-louhi-reads.md`, section 2), per space (`lugh/scope`,
  `lugh/secrets`, the back-off space), as a query and a notice:
  - The notice drives `/ready`.
  - The query goes before genesis, POSIX number allocation and unique-name writes, which are refused until caught up.
  - Sign-in, token and bind decisions answer 503 rather than read a lagging view.
  - It compares only with peers that open the space, and keeps "no active peers" distinct from caught up.
  It belongs to P8.1 and P8.3.
- **Dagda's follower-lag fix** (slice 2) for P8.5: a disable seen on another node within about a second (the maintainer,
  2026-11-14).
- **Dagda's switch for its tools** (agreed, its next release). Until then the fetched node build compiles `dagda-migrate`
  and `dagda-bench`, and a local install carries `dagda-migrate`.
- **The maintainer, at P13**: `docs/architecture.md` question 10 (TLS for T.O.M.S sites, or sign-in only at the hub).

## Open, not scheduled

- **Principal events over Lir**, and the status read `lugh:principals.status` (`2026-11-15-principal-events.md`; asked by
  Mimir and Louhi). Recommended after P8.1, on Lir's `lir::client`.
- **Hashing on `sched::WorkerPool`**, at P8.1. Until then the hashing queue is unbounded, a known gap.
- **Socket activation** for the listeners, deferred: `inherited_socket` checks LISTEN_PID, which a test cannot set.
- **lugh_client as an installed package** (`find_package(lugh)`, asked by Kvasir), with a `lugh-dev` Debian package.
- Small: whether the remaining synchronous `Result` returns (config loader, record codecs) should throw.

## Dependencies pinned (develop)

| Dependency | Pin | Used by |
|---|---|---|
| Dannan | 0.10.2 (`LUGH_DANNAN_REF`) | everything |
| Dagda | 0.3.2 (`LUGH_DAGDA_REF`) | the tests only; the node does not link it until P8 |
| Lir | 0.1.0 (`LUGH_LIR_REF`) | the tests and `lugh::client_topics` only |

Each comes from the sibling checkout (`../dannan`, `../dagda`, `../lir`), cloned into the build tree. A relying party that
fetches lugh_client alone (`LUGH_BUILD_NODE=OFF`) fetches Dannan and nothing else. The package build uses the installed
Dannan (`LUGH_SYSTEM_DEPENDENCIES`).

## Builds and tests

No builds or tests on the development workstation, only on the shared arm64 build nodes (the maintainer, 2026-11-14), and
no clangd indexer either (kill this session's after a C++ edit). How to reach the nodes and their claim board is in the
gitignored `CLAUDE.local.md`; real host names and addresses never go in the repository. A job claims only the cores it uses,
runs at `nice -n 19`, and releases its claim when it ends or fails.

Each feature or milestone ends green once each in debug, ASan with UBSan and TSan, on the same code, before it merges into
`develop`, with Dannan, Dagda and Lir built instrumented. Sanitizers run then, for a release, or to diagnose a named bug.
Test once: no repeated runs; a test that fails at random is investigated, never tolerated (the maintainer, 2026-11-20). A
release adds the fuzz campaigns and, while packaged, the package build with its tests. A gate carries across a version
bump only when a diff shows the code is the same.

GitHub CI runs on pushes to `develop` and `main` and on pull requests, not for TODO, docs or Markdown changes; CodeQL on
`main` and weekly. All green: CI on `develop` and `main`, CodeQL on `main` since 0.3.0.

Lugh runs as a single-node test service on all four build nodes, each its own genesis (root's password in
`/root/lugh-root-password` there). It came through the cluster's wipe (2026-11-18) and two nodes' unclean power loss
(2026-11-20) with its store intact.

## Documents

Live:
- `2026-11-13-p8-plan.md`: P8, steps P8.0 to P8.9, the maintainer's rulings (TOTP on agreement registers, the named
  acknowledgement levels).
- `2026-11-13-lugh-needs-of-the-stack.md`: what Lugh needs of Dannan (N1 to N10) and Dagda (G1 to G15), with the answers.
- `2026-11-20-dependants.md`: what each dependant needs of Lugh, and the shared admin UI.
- `2026-11-15-principal-events.md`: principal changes over Lir, and the status read. A design.
- `../dagda/TODO/2026-11-03-stack.md`: what each project of the stack owns.

Done, kept as the design record (source comments cite them by path): `2026-11-20-client-relying-party.md`,
`2026-11-16-p12-hardening.md` (P12), `2026-11-16-p7-dashboard.md` (P7), `2026-11-15-self-factors.md`,
`2026-11-15-p11-webauthn.md` (P11), `2026-11-15-dannan-0.8.md`, `2026-11-14-p10-plan.md` (P10), `2026-11-04-oauth.md`
(P6), `2026-11-04-ldap.md` (P9).

Other repository documents: `docs/packaging.md` (the Debian package), `docs/client.md` (lugh_client), and the
architecture, API, OAuth, LDAP and threat-model documents in `docs/`.

## Standing decisions

The ones that shape the next work; the rest are in the plans and `COMPLETED.md`.

- No special-case code for a single node: every project is a leaderless, multi-master soft cluster (the maintainer,
  2026-11-20).
- No duplicated functionality: the deepest shared dependency owns a piece, and of two projects that depend on each
  other the lower keeps it. When a dependency's release adds what Lugh wrote itself, Lugh moves onto it.
- Every service's configuration is YAML through `dannan::config`, with flags and environment variables as overrides,
  named from the YAML key (Dannan's `docs/config.md`); the variable prefix is `LUGH`.
- About 100% code coverage (the maintainer, 2026-11-20), measured by `LUGH_COVERAGE` and CI's coverage job to Codecov.
- GoogleTest for all C++ tests; the admin React uses Vitest.
- Passwords follow the usual standards: no promise about their characters, ever.
- Features and milestones are developed on branches and squash-merged into `develop` when complete.
- Versions are written in full, `x.y.z`, in pins, requests, docs and messages; a Debian range is the one range.
- Releases: the README is about installing and using Lugh; `CHANGELOG.md` gets each release's entry before its tag,
  with a line for each dependency repin; minor or patch bumps only; a release badge.
- Nothing identifying in tracked files or commit messages: no host names, addresses, user paths, session names, or the
  maintainer's name outside copyright notices (the history was scrubbed 2026-11-20).
- The sealed store, keyring, `Files`, `Console` and the node's start-up stay coroutines and frozen until Dagda carries
  Lugh's spaces, then are deleted.
- Lugh's domains are `lugh/scope` (every node a member) and `lugh/secrets` (Lugh nodes). TOTP and recovery codes
  become agreement registers, failing closed on a minority side (the maintainer, 2026-11-15).
- `lugh_client` links Dannan and knows nothing of Lir; Lir's MQTT permissions are Lugh topic scopes, checked by
  `lugh::client_topics` on Lir's codec.
- WebAuthn is offered only when `oauth.issuer` is set, whose host is the RP ID.

## Plan

| ID | Phase | State |
|---|---|---|
| P1 to P6 | Skeleton, keys, sealed store, directory and sign-in, the API, OAuth and OIDC | done (P3 frozen until P8) |
| P7 | Dashboard; administering through a session needs `phr` | done |
| P8 | The cluster on the stack: Dannan's `Context`, Dagda's spaces, replacing the sealed store and keyring | P8.0 done; the rest waits on Dannan and Dagda |
| P9 | Writable LDAP | done |
| P10 | `lugh_client` | done; relying-party pieces and topic checks added 2026-11-20 |
| P11 | WebAuthn, passkeys and `phr` | done |
| P12 | Hardening: fuzzing, the sandbox, key rotation drills, the threat model | done |
| P13 | SSO rollout: blackraven-admin, T.O.M.S, AthenaSIP admin, Macha; one break-glass account each | not started |
