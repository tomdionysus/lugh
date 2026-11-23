# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here (2026-11-22)

**Releases.** 0.2.0 (packaged), 0.3.0 (Dannan 0.10.0), 0.4.0 (the stack's config names), 0.5.0 (onto the rest of
Dannan 0.10.x) and 0.6.0 (Dannan 0.11.0 and `@lugh/admin-ui`; source only) are tagged on `main`; `CHANGELOG.md` says what each holds. Main and release tags are pushed
once a release's gate is green, without asking (the maintainer, 2026-11-22).

The dependants (Louhi, Kvasir, Mimir, Lir's plugin) were told of each change before it landed and at each tag; none
needs a change now.

**The Debian package:** none in the apt repository since 0.2.0. Its wait is over (the coordinator, 2026-11-23): Dagda
0.4.0 is tagged on Dannan 0.11.1, the pair the package build tests against. 0.5.0's was built locally with `nocheck`
(`COMPLETED.md`, 2026-11-22); the next release's is built with its tests, against Dannan 0.11.1's and Dagda 0.4.0's
debs (from the apt repository, or built from their tags in a container), then lintian and the install test. Putting
it in the apt repository waits on the maintainer's word.

**Onto Dannan 0.10.x: done in 0.5.0** (`COMPLETED.md`, 2026-11-22). Not taken: `agree::MemoryStore`, `each_held` and
the agreement teardown fixes, which are P8's; the ack levels.

**Next, not blocked:**
1. ~~Louhi's trial on node-c's Lugh~~ and ~~Dannan 0.11.1 with Dagda 0.4.0~~: done (`COMPLETED.md`, 2026-11-23).
2. Coverage.
3. The next release's Debian package, with its tests, against Dannan 0.11.1's and Dagda 0.4.0's debs. Dagda 0.4.0's are in
   the tomcully.com apt repository for arm64 (`libdagda0.4.0`, `libdagda-dev`, `dagda-tools`; amd64 waits on the
   maintainer), so the arm64 build installs them from there.
P8 waits on Dannan and Dagda. Settled: the synchronous `Result` returns (the config loader, the record codecs) stay as
they are, per CONTRIBUTING's errors rule: what happened returns its result.

**Also waiting to be done, not blocked:**
- `@lugh/admin-ui`'s later asks, each from one consumer alone (theirs to build unless another asks): Lir's payload
  viewer, Mimir's number tile with a sparkline and monospace editor, Louhi's read-only JSON view.
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

## Dependencies pinned (develop)

| Dependency | Pin | Used by |
|---|---|---|
| Dannan | 0.11.1 (`LUGH_DANNAN_REF`; 0.6.0 is on 0.11.0) | everything |
| Dagda | 0.4.0 (`LUGH_DAGDA_REF`; 0.6.0's tests used 0.3.2) | the tests only; the node does not link it until P8 |
| Lir | 0.2.0 (`LUGH_LIR_REF`) | the tests and `lugh::client_topics` only |

Each comes from the sibling checkout (`../dannan`, `../dagda`, `../lir`), cloned into the build tree. A relying party that
fetches lugh_client alone (`LUGH_BUILD_NODE=OFF`) fetches Dannan and nothing else. The package build uses the installed
Dannan (`LUGH_SYSTEM_DEPENDENCIES`).

## Builds and tests

No builds or tests on the development workstation, only on the shared arm64 build nodes (the maintainer, 2026-11-14), and
no clangd indexer either (kill this session's after a C++ edit). How to reach the nodes and their claim board is in the
gitignored `CLAUDE.local.md`; real host names and addresses never go in the repository. A job claims only the cores it uses,
runs at `nice -n 19`, and releases its claim when it ends or fails.

No node is preferred (the maintainer, 2026-11-23): a job takes whichever node has the cores free now, never queues for one
because it holds a warm build tree, an earlier build or a habit, and on a node that lacks a tool or a `-dev` package
installs it (1 core claimed, `nice -n 19 apt-get install -y`, a board note naming the package and the node). The trees are
synced there and built from scratch. A job waits only when no node has the cores, and then names every node it can run on
(`--any`). The exceptions are jobs that genuinely need one node, said in the claim's job text: a service that lives on it
(a node's Lugh test service), or memory (the 4 GB node takes no sanitizer, fuzz or coverage build).

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
