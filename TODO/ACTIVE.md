# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here (2026-11-15, end of session)

**P11 (WebAuthn, passkeys, `phr`) is done**: debug, ASan and TSan each green at 784 tests on the final code, and
`feature/webauthn` merged into `develop` (not pushed; ask the maintainer before pushing). Its record is `COMPLETED.md`, "2026-11-15: P11",
and its plan with the maintainer's rulings is `2026-11-15-p11-webauthn.md`.

Still uncommitted, on purpose: `lugh/fuzz/client_fuzz.cpp`, `lugh/fuzz/webauthn_fuzz.cpp` and their lines in
`lugh/fuzz/CMakeLists.txt`. They wait until every fuzz target is built on node-a's clang (P12).

After P11, the next phase is the maintainer's choice. P7, the dashboard, is unblocked (he put it after P11); P12 is the other candidate. P8
waits on Dagda.

## Open, not scheduled

- **`lugh/client/https.cpp` onto Dannan's `StreamConnector`**, which is now in the pinned 0.8.3, with a `ClientTrust` built at
  start. Its face and tests stay.
- **Adding a key after enrolment** (`/signin/factors`), which P11's plan named, and re-authentication before a factor change.
- **Socket activation** for the listeners. Deferred, since `inherited_socket` checks LISTEN_PID and a test cannot set it
  (`2026-11-15-dannan-0.8.md`).
- **Root's first sign-in enrolling WebAuthn**: at P7 (the maintainer, 2026-11-15).
- **Principal events over Lir**, and the narrow status read `lugh:principals.status` (the maintainer, 2026-11-15, asked by Mimir and Louhi):
  `2026-11-15-principal-events.md`. Recommended after P8.1. The MQTT client is Lir's `lir::client`.
- **Hashing on `sched::WorkerPool`**, at P8.1. Until then the hashing queue is unbounded, a known gap.

## Waiting on others

- **Dagda** is paused for Macha's port (the maintainer, 2026-11-14). Its slice 1 is tagged 0.2.0 locally and not pushed; P8.0 to P8.4 start on
  it (`2026-11-13-p8-plan.md`). P8.5 also waits on the follower-lag fix (slice 2): a disable must be seen on another build node within about
  a second (the maintainer, 2026-11-14).
- **Dannan 0.9.0's agreement primitive.** TOTP, recovery codes and key rotation become registers on it, with no interim lease or
  workaround (the maintainer, 2026-11-15). Lugh is a reviewed consumer in Dannan's agreement design.
- **The maintainer, at P13**: `docs/architecture.md` question 10 (TLS for T.O.M.S sites, or sign-in only at the hub).
- **Not merged, by the maintainer's choice**: GitHub's `main` carries aaac977 (Alpine and OpenRC for Raven). Raven is dropped for now (the maintainer,
  2026-11-13); when it returns, merge `origin/main` into `develop` (about ten conflicts), test, fast-forward `main`, push.
- **Not yet tried on Linux**: `LoadCredentialEncrypted=`, `LimitMEMLOCK` and `MADV_DONTDUMP`. No fuzz target has been built yet.

## Dependencies pinned

- Dannan **0.8.3** (`LUGH_DANNAN_REF`, a tag in `../dannan`), giving:
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
| node-a `.11` | TSan only: clang 19, 4K pages, `~/lugh/build-tsan`. Usually busy with Dagda; queue for it |
| node-b `.12` | `~/lugh/build` (debug) and `~/lugh/build-asan` |
| node-d `.14` | `~/lugh/build` (debug), 4 GB, Node 20.19 |
| node-c `.13` | Not Lugh's; LED Config's services, no reboots |

The claim board (0.2.0):
- `claims_list`, then `claim_take` with only the cores the job needs, and `-j` no more than those. `until` is honest.
- When nothing is free, one background `claim-board wait <hosts> --cores N --job "..." --for 90m`. One wait per session.
- Release the claim when the job ends or fails.
- Sync with `rsync -rlpgoD --delete --exclude '/build*/' --exclude /.git/ --exclude /.cache/`, never `-a` (mtimes fool make).
- `chown -R builder:builder`, then run as the build user under `nice -n 19`.
- Run the tests only if the build succeeded, or a failed build reports the old binary's results.

## Documents

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
| P7 | Dashboard, the React SPA in T.O.M.S's styling, requiring `phr`. Root's first sign-in enrols WebAuthn here. Tests: GoogleTest for the server side, Vitest for components and `lib/API.ts`, Playwright against a real `lugh-node`. Node to be installed on node-b (the maintainer, 2026-11-15) | next candidate |
| P8 | The cluster on the stack: Dannan's `Context`, Dagda's spaces, replacing the sealed store and keyring (`2026-11-13-p8-plan.md`) | planned, waits on Dagda |
| P9 | Writable LDAP | done |
| P10 | `lugh_client` | done |
| P11 | WebAuthn, passkeys and `phr` (`2026-11-15-p11-webauthn.md`) | done |
| P12 | Hardening: fuzzing campaigns (build every target on node-a first), sandbox review, key rotation drills, threat model | not started |
| P13 | SSO rollout: blackraven-admin, T.O.M.S, AthenaSIP admin, Macha; one break-glass account each | not started |
