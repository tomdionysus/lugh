# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here (2026-11-16)

**P12, hardening, is done** (`COMPLETED.md`, "2026-11-16: P12"; plan `2026-11-16-p12-hardening.md`), merged into `develop` and
pushed. P7 before it is done too. Lugh runs as a test service on all four build nodes, each its own genesis; root's password for each is in
`/root/lugh-root-password` there.

Left from P12: hour-long fuzz campaigns, and binary seeds for the record and protocol targets.

Next is the maintainer's choice: P13 (the SSO rollout) or P8 (the cluster on Dagda, which waits on Dagda).

## Open, not scheduled

- **Socket activation** for the listeners. Deferred, since `inherited_socket` checks LISTEN_PID and a test cannot set it
  (`2026-11-15-dannan-0.8.md`).
- **Principal events over Lir**, and the narrow status read `lugh:principals.status` (the maintainer, 2026-11-15, asked by Mimir and Louhi):
  `2026-11-15-principal-events.md`. Recommended after P8.1. The MQTT client is Lir's `lir::client`.
- **(done) `authn::Backoff` into Dannan** as `dannan::listen::Backoff` in 0.9 (asked by Kvasir, agreed by Dannan and Lugh, 2026-11-16,
  stack rule 3; its time point becomes Dannan's `contract::TimePoint`): when 0.9 is tagged, move the pin, switch the
  authenticator, and delete `lugh/authn/backoff.h` with `authn_backoff_test.cpp` (its 5 tests go to Dannan; record the drop).
  Summing failures across the cluster stays Lugh's (P8). The maintainer chose a patch: it comes in Dannan 0.8.5
  (in its gate, 2026-11-16; 0.8.4 is out, ABI kept, nothing Lugh needs). When 0.8.5 is tagged, move the pin to it and switch.
- **Hashing on `sched::WorkerPool`**, at P8.1. Until then the hashing queue is unbounded, a known gap.

## Waiting on others

- **Dagda** (asked 2026-11-16): slice 1 is built, gated and tagged 0.2.0 locally, not pushed; P8.0 can start on it the day the maintainer
  releases it, which he ruled waits until Macha runs on Dagda as well as before, proven. Dagda's repair redesign (2026-11-16)
  changes nothing P8.0 to P8.4 relies on; whether a large value can ever leave the head for a data object is unverified on
  Dagda's side. Dagda is paused for Macha's port (the maintainer, 2026-11-14). Its slice 1 is tagged 0.2.0 locally and not pushed; P8.0 to P8.4 start on
  it (`2026-11-13-p8-plan.md`). P8.5 also waits on the follower-lag fix (slice 2): a disable must be seen on another build node within about
  a second (the maintainer, 2026-11-14).
- **Dannan 0.9.0's agreement primitive.** TOTP, recovery codes and key rotation become registers on it, with no interim lease or
  workaround (the maintainer, 2026-11-15). Lugh is a reviewed consumer in Dannan's agreement design.
- **The maintainer, at P13**: `docs/architecture.md` question 10 (TLS for T.O.M.S sites, or sign-in only at the hub).
- **Not merged, by the maintainer's choice**: GitHub's `main` carries aaac977 (Alpine and OpenRC for Raven). Raven is dropped for now (the maintainer,
  2026-11-13); when it returns, merge `origin/main` into `develop` (about ten conflicts), test, fast-forward `main`, push.

## Dependencies pinned

- Dannan **0.8.5** (`LUGH_DANNAN_REF`, a tag in `../dannan`), giving the sign-in back-off besides:
  - the listener and the connector;
  - `verify_rs256`;
  - the worker pool.
  Its ABI is 0.8.0's. Move the pin when a tag Lugh wants is cut.
- Lir's Lugh plugin pins a `develop` commit of Lugh, and repins at Lugh's first release.

## The build node cluster

**No builds or tests on the Mac**, only here (the maintainer, 2026-11-14). The four machines (Debian 13 arm64, GCC 14, Boost 1.83) are shared
by every session; Lugh's things are under `/srv/build/lugh`, with the source in `/srv/build/lugh/lugh` and a copy of Dannan's history
in `/srv/build/lugh/dannan` (rsync `../dannan/.git/` there when a new tag is pinned).

| Machine | Lugh's use |
|---|---|
| node-a `.11` | TSan: clang 19, `~/lugh/build-tsan`. Often busy with Dagda; queue for it |
| node-b `.12` | `~/lugh/build` (debug), `~/lugh/build-asan`, `~/lugh/build-fuzz` (clang), Node 20.19 and Playwright's Chromium (the dashboard) |
| node-d `.14` | `~/lugh/build` (debug), 4 GB, Node 20.19. No sanitizer builds: it runs out of memory |

Since 2026-11-16 every build node runs a 4K-page, 48-bit-VA kernel (6.18.62-v8-va48+): ASan, UBSan and TSan all work under g++ and
clang 19 on any of them (node-d has no clang, and is too small for sanitizer builds). Delete a build tree's `*.gch` after a kernel
change, or GCC crashes on its old precompiled headers. TSan on the Mac only to hunt a specific bug (the maintainer, 2026-11-16).

The claim board (0.2.0):
- `claims_list`, then `claim_take` with only the cores the job needs, and `-j` no more than those. `until` is honest.
- When nothing is free, one background `claim-board wait <hosts> --cores N --job "..." --for 90m`. One wait per session.
- Release the claim when the job ends or fails.
- Sync with `rsync -rlpgoD --delete --exclude '/build*/' --exclude /.git/ --exclude /.cache/`, never `-a` (mtimes fool make).
- `chown -R builder:builder`, then run as the build user under `nice -n 19`.
- Run the tests only if the build succeeded, or a failed build reports the old binary's results.

## Documents

- `2026-11-16-p12-hardening.md`: P12, hardening. Done.
- `2026-11-16-p7-dashboard.md`: P7, the dashboard, with the maintainer's rulings (phr on the server for administering; root offered both). Done.
- `2026-11-15-self-factors.md`: a person's own factors and the re-authentication window, with the maintainer's rulings. Done.
- `2026-11-15-p11-webauthn.md`: P11, its steps W1 to W7, the maintainer's rulings and progress.
- `2026-11-13-p8-plan.md`: P8, the rewrite against Dagda's spaces, steps P8.0 to P8.9, the maintainer's rulings (TOTP on agreement registers,
  the named acknowledgement levels).
- `2026-11-13-lugh-needs-of-the-stack.md`: what Lugh needs of Dannan (N1 to N10) and Dagda (G1 to G15), with the answers.
- `2026-11-15-principal-events.md`: principal changes over Lir, and the status read. A design.
- `2026-11-15-dannan-0.8.md`: the listeners onto `dannan::listen`, steps A to E, done.
- `2026-11-14-p10-plan.md`, `2026-11-04-oauth.md`, `2026-11-04-ldap.md`: the P10, P6 and P9 plans, done; kept as the design record.
- `../dagda/TODO/2026-11-03-stack.md`: what each project of the stack owns.

## Standing decisions

The ones that shape the next work; the rest are in the plans and `COMPLETED.md`.

- The sealed store, keyring, `Files`, `Console` and the node's start-up stay coroutines and frozen until Dagda carries Lugh's spaces,
  then are deleted ("Keep the store until Dagda").
- Lugh's domains are `lugh/scope` (every node a member) and `lugh/secrets` (Lugh nodes). Credential changes and revocations are
  Replicated, answering "applied, n nodes pending".
- TOTP and recovery codes become agreement registers, failing closed on a minority side.
- Logs, Status and docs name acknowledgement levels as the stack's standard does (`ephemeral`, `persisted`, `decided`,
  `replicated`; setting `ack_level`).
- Lugh installs Dannan's `ScopeSource`; message types from 512; one `lugh-node` per node; HTTP stays Lugh's.
- `lugh_client` links Dannan and knows nothing of Lir; Lir's MQTT permissions are Lugh topic scopes.
- WebAuthn is offered only when `oauth.issuer` is set, whose host is the RP ID.
- Left to decide, small: whether the remaining synchronous `Result` returns (config loader, record codecs) should throw.

## Plan

Each phase ends green in debug, ASan with leak detection and TSan, one full run each, on the same code, and a commit. New tests
that touch threads, timing or processes are repeated on their own with a filter (20 times) in each build; nothing else is run twice
without a reason (the maintainer, 2026-11-14).

| ID | Phase | State |
|---|---|---|
| P1 to P6 | Skeleton, keys, sealed store, directory and sign-in, the API, OAuth and OIDC | done (P3 frozen until P8) |
| P7 | Dashboard, the React SPA in T.O.M.S's styling; administering through a session needs `phr` (`2026-11-16-p7-dashboard.md`) | done |
| P8 | The cluster on the stack: Dannan's `Context`, Dagda's spaces, replacing the sealed store and keyring (`2026-11-13-p8-plan.md`) | planned, waits on Dagda |
| P9 | Writable LDAP | done |
| P10 | `lugh_client` | done |
| P11 | WebAuthn, passkeys and `phr` (`2026-11-15-p11-webauthn.md`) | done |
| P12 | Hardening: fuzzing, the sandbox on real hosts, key rotation drills, the threat model (`2026-11-16-p12-hardening.md`) | done |
| P13 | SSO rollout: blackraven-admin, T.O.M.S, AthenaSIP admin, Macha; one break-glass account each | not started |
