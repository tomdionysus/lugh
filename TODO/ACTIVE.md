# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here (2026-11-20)

**Lugh is idle, waiting for the maintainer's word to start P8** (the cluster on Dagda, `2026-11-13-p8-plan.md`). P1 to P7 and P9 to P12 are
done and merged into `develop`, which is pushed. The maintainer's ruling of 2026-11-17: Lugh waits for Dagda's release, with no P8 prep and
not P13.

What changed since that ruling, for the maintainer to rule on:
- Dagda pushed 0.3.1 and 0.3.2 (2026-11-19 and 20). Its notes say 0.3.1 carries slice 1, which P8.0 to P8.4 need; telling Lugh is
  on Dagda's "Waiting on the maintainer" list. Its `0.2.0` tag stays local. The slices after 1 are paused in Dagda.
- Dannan 0.9.2 is tagged (a gossip fix: an advert reaches a peer met after it was set). Dagda 0.3.x builds on it; Lugh is on 0.9.1
  and moves with Dagda at P8.0.

Lugh runs as a single-node test service on all four build nodes, each its own genesis; root's password for each is in
`/root/lugh-root-password` there. The service survived the cluster's wipe (2026-11-18; health 200 on all four, checked).

Before Lugh's first release: the fuzz campaigns again, on the instrumented build (P12 plan, "Left for the first release").

## Open, not scheduled

- **Socket activation** for the listeners. Deferred, since `inherited_socket` checks LISTEN_PID and a test cannot set it
  (`2026-11-15-dannan-0.8.md`).
- **Principal events over Lir**, and the narrow status read `lugh:principals.status` (the maintainer, 2026-11-15, asked by Mimir and Louhi):
  `2026-11-15-principal-events.md`. Recommended after P8.1. The MQTT client is Lir's `lir::client`.
- **Hashing on `sched::WorkerPool`**, at P8.1. Until then the hashing queue is unbounded, a known gap.
- Small, left to decide: whether the remaining synchronous `Result` returns (config loader, record codecs) should throw.

## Waiting on others

- **Dagda**: see "Resume here". Dagda checked (2026-11-16) that no path moves a head value into a DATA object at any size; not
  checked: how a 256 KiB value affects a tree node's size and splitting, a test at P8.0. P8.5 also waits on the follower-lag fix
  (slice 2): a disable seen on another build node within about a second (the maintainer, 2026-11-14). Dagda will tell Lugh when `Space::covers()` is
  the way to compare a view with what Lugh wrote (its Next 3).
- **Dagda's caught-up signal** (asked by Dagda 2026-11-20 for Louhi; design `../dagda/TODO/2026-11-20-louhi-reads.md`, section 2).
  Lugh answered that it needs it for `lugh/scope`, `lugh/secrets` and the back-off space, per space, as a query and a notice:
  - The notice drives `/ready`.
  - The query goes before genesis and before POSIX number allocation or a unique-name write, which are refused until caught up.
  - Sign-in, token and bind decisions answer 503 rather than read a lagging view.
  - Asked of Dagda: compare only with peers that open the space (a Macha-only node never holds back `lugh/secrets`), keep "no
    active peers" distinct from caught up, and recompute it when the active set changes.
  - The 40-byte head-identity advert serves Lugh.
  Belongs to P8.1 and P8.3.
- **The maintainer, at P13**: `docs/architecture.md` question 10 (TLS for T.O.M.S sites, or sign-in only at the hub).
- **Not merged, by the maintainer's choice**: GitHub's `main` carries aaac977 (Alpine and OpenRC for Raven). Raven is dropped for now (the maintainer,
  2026-11-13); when it returns, merge `origin/main` into `develop` (about ten conflicts), test, fast-forward `main`, push.

## Dependencies pinned

- Dannan **0.9.1** (`LUGH_DANNAN_REF`, a tag in `../dannan`, ABI `libdannan.so.0.9`): agreement with `Outcome::unknown` for P8's
  registers, the listener and connector, `verify_rs256`, the worker pool, the sign-in back-off. Move the pin when a tag Lugh wants
  is cut.
- Lir's Lugh plugin pins a `develop` commit of Lugh, and repins at Lugh's first release.

## The build node cluster

**No builds or tests on the Mac**, only on the build nodes (the maintainer, 2026-11-14), and no clangd indexer either (kill this session's after a C++
edit). The four (Debian 13 arm64, kernel 6.18.62-v8-va48+, 4K pages, 48-bit VA) are shared by every session:

| Machine | Memory | Note |
|---|---|---|
| node-a `.11` | 16 GB | |
| node-b `.12` | 16 GB | |
| node-c `.13` | 16 GB | |
| node-d `.14` | 4 GB | no sanitizer builds (out of memory), `-j2` |

**Wiped to bare OS on 2026-11-18**: Lugh has nothing on them but the installed service. `/srv/build/lugh` (the source, Dannan's
history, every build tree), Node and Playwright are gone. The toolchain is back on all four: GCC 14, clang 19, CMake 3.31, Ninja,
Boost 1.83, OpenSSL 3.5, yaml-cpp 0.8, GoogleTest 1.16. To build again: rsync the source to `/srv/build/lugh/lugh` and
`../dannan/.git/` to `/srv/build/lugh/dannan` (it must carry the pinned tag), configure, build. The dashboard's tests need Node 20 and
Playwright's Chromium installed again.

The claim board:
- `claims_list`, then `claim_take` (its own tool call) with only the cores the job needs, and `-j` no more than those, `nice -n 19`.
  `until` is honest.
- When nothing is free, one background `claim-board wait <hosts> --cores N --job "..." --for 90m`. One wait per session.
- Release the claim when the job ends or fails.
- Sync with `rsync -rlpgoD --delete --exclude '/build*/' --exclude /.git/ --exclude /.cache/`, never `-a` (mtimes fool make).
- `chown -R builder:builder`, then run as the build user.
- Run the tests only if the build succeeded, or a failed build reports the old binary's results.

Sanitizers only at a phase's end, for a release, or to hunt a named bug; never for a pin move or another step's gate (the maintainer's rule,
restated by the cluster 2026-11-17; Lugh's phase-end exception is `CLAUDE.md`'s).

## Documents

Live:
- `2026-11-13-p8-plan.md`: P8, the rewrite against Dagda's spaces, steps P8.0 to P8.9, the maintainer's rulings (TOTP on agreement registers,
  the named acknowledgement levels).
- `2026-11-13-lugh-needs-of-the-stack.md`: what Lugh needs of Dannan (N1 to N10) and Dagda (G1 to G15), with the answers.
- `2026-11-15-principal-events.md`: principal changes over Lir, and the status read. A design.
- `../dagda/TODO/2026-11-03-stack.md`: what each project of the stack owns.

Done, kept as the design record: `2026-11-16-p12-hardening.md` (P12), `2026-11-16-p7-dashboard.md` (P7),
`2026-11-15-self-factors.md`, `2026-11-15-p11-webauthn.md` (P11), `2026-11-15-dannan-0.8.md`, `2026-11-14-p10-plan.md` (P10),
`2026-11-04-oauth.md` (P6), `2026-11-04-ldap.md` (P9).

## Standing decisions

The ones that shape the next work; the rest are in the plans and `COMPLETED.md`.

- The sealed store, keyring, `Files`, `Console` and the node's start-up stay coroutines and frozen until Dagda carries Lugh's spaces,
  then are deleted ("Keep the store until Dagda").
- Lugh's domains are `lugh/scope` (every node a member) and `lugh/secrets` (Lugh nodes). Credential changes and revocations are
  Replicated, answering "applied, n nodes pending".
- TOTP and recovery codes become agreement registers, failing closed on a minority side, with no interim lease (the maintainer, 2026-11-15).
- Logs, Status and docs name acknowledgement levels as the stack's standard does (`ephemeral`, `persisted`, `decided`,
  `replicated`; setting `ack_level`).
- Lugh installs Dannan's `ScopeSource`; message types from 512; one `lugh-node` per node; HTTP stays Lugh's.
- `lugh_client` links Dannan and knows nothing of Lir; Lir's MQTT permissions are Lugh topic scopes.
- WebAuthn is offered only when `oauth.issuer` is set, whose host is the RP ID.

## Plan

Each phase ends green in debug, ASan with leak detection and TSan, one full run each, on the same code, and a commit. New tests
that touch threads, timing or processes are repeated on their own with a filter (20 times) in each build; nothing else is run twice
without a reason (the maintainer, 2026-11-14).

| ID | Phase | State |
|---|---|---|
| P1 to P6 | Skeleton, keys, sealed store, directory and sign-in, the API, OAuth and OIDC | done (P3 frozen until P8) |
| P7 | Dashboard, the React SPA in T.O.M.S's styling; administering through a session needs `phr` | done |
| P8 | The cluster on the stack: Dannan's `Context`, Dagda's spaces, replacing the sealed store and keyring | planned, waits on the maintainer's word |
| P9 | Writable LDAP | done |
| P10 | `lugh_client` | done |
| P11 | WebAuthn, passkeys and `phr` | done |
| P12 | Hardening: fuzzing, the sandbox on real hosts, key rotation drills, the threat model | done; campaigns again before release |
| P13 | SSO rollout: blackraven-admin, T.O.M.S, AthenaSIP admin, Macha; one break-glass account each | not started |
