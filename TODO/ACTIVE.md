# Active work

What is being worked on now and what comes next. When an item ships, move it to `COMPLETED.md` with the date and the outcome.

## Resume here (2026-11-20)

**0.2.0 is released** (tag on `main`; `COMPLETED.md`), against Dannan 0.9.2, Dagda 0.3.2 and lir::mqtt d36356d (Lir's 0.1.0
was not yet on GitHub). Its .deb is built and tested but not in the apt repository: the maintainer said not yet. Next release:
repin lir::mqtt to Lir's tag, then Dannan 0.10.0 and Dagda's next.

**P8.0 is done and merged into `develop`** (2026-11-20, the maintainer's word "Start P8.0 now"; `COMPLETED.md`). Dagda 0.3.2 is fetched
beside Dannan 0.9.2, and `ClusterRig` (`lugh/test/fixtures/cluster_rig.h`) runs Lugh's spaces on Dagda's in-process cluster.

**What comes next, and what it waits on.** The rest of P8 is held by its dependencies, by the no-duplication rule:
- P8.1 (lugh-node a Dannan node) waits on Dannan's node-program helper and founding act (Dannan's plan, items 4 and 14), so
  Lugh writes no wiring of its own that they would replace. Dannan 0.10.0 is under way; its tag needs the maintainer's word.
- P8.2 to P8.4 wait on Dagda's register map (D6, being built test-first), which replaces Lugh's own merge and codec.
- P8.5 waits on Dagda's slice 2; P8.6 on the durable AcceptorStore and Dannan's register layer; P8.7 on D9.
Meanwhile, not waiting (`lugh::client_topics` is done):
`@lugh/admin-ui`, the dashboard's shell carved into a package for Lir, Louhi, Mimir and Kvasir (`2026-11-20-dependants.md`).
**Dannan 0.10.0, reviewed against its CHANGELOG** (`feature/dannan-0.10`; gated once its tag, and Dagda 0.4.0's, are out).
With the pin:
- `LUGH_SANITIZE` is passed through as `DANNAN_SANITIZE`, beside Lugh's global flags.
- `TokenSource`'s retry policy is Dannan's `RetryPolicy::unbounded(5s, 5min)`, the same policy Lugh wrote by hand.
- The rest of the diff is source-compatible: `identity::hex` and `unhex` forward to `encoding/base.h`, and the durable-file
  calls gain a defaulted mode.

Each next item is its own step, because each changes behaviour or public API, in this order:
1. **The callback vocabulary.** lugh_client's and the node's `Outcome`, `Fault` and `Completion` become Dannan's
   `contract/completion.h` (one Fault kind for the stack, with `unavailable` and `timed_out` mapped to 503). This changes
   lugh_client's public types, so it is told to Louhi, Kvasir, Mimir and Lir first.
2. **The encodings.** `lugh/core/encoding.h` (base64url, base32, `printable`, UTF-8) becomes `encoding/base.h`; Dannan's
   exact decoders write a secret straight into a `SecureBuffer`.
3. **TOTP's HMAC-SHA-1** becomes `identity::hmac_sha1`.
4. **Lugh's random IDs** become `identity::RandomId<Tag>`, one type per kind.
5. **`network::Cidr`** becomes `listen::Prefix`, which now refuses host bits set past the length. A configured
   `proxy.trusted_networks: 10.0.0.1/8`, read today as 10.0.0.0/8, would stop the start; the release notes say so.
6. **The tests' `RecordingSink`** becomes `test::RecordingSink`, and lugh_node's late logger swap becomes
   `status::SwappableSink`.
7. Any directory Lugh makes and syncs by hand (the keyring's and state files') uses `identity::durable_create_directories`
   and `durable_sync_directory`.
8. Lugh's fuzz targets also run as smoke tests inside `lugh_tests`, through `dannan::testing` (`fuzz::smoke`), so every
   CI run exercises each parser's corpus; `lugh/fuzz/campaign.sh` keeps the long campaigns.
Not taken: `agree::MemoryStore` and the agreement teardown fixes, which are P8's (Lugh hosts no agreement yet); the ack
levels, which Lugh does not name.

**The stack's config names** (Dannan's `docs/config.md`). The layer order and the log keys already conform. Four flags
and variables do not: each is to be made from its full dotted key.
- `server.address`: `--address` and `LUGH_ADDRESS` become `--server-address` and `LUGH_SERVER_ADDRESS`.
- `server.port`: `--port` and `LUGH_PORT` become `--server-port` and `LUGH_SERVER_PORT`.
- `oauth.issuer`: `--issuer` and `LUGH_ISSUER` become `--oauth-issuer` and `LUGH_OAUTH_ISSUER`.
- `oauth.mtls_port`: `--mtls-port` and `LUGH_MTLS_PORT` become `--oauth-mtls-port` and `LUGH_OAUTH_MTLS_PORT`.

A flag is part of the interface, so the renames go in the next minor, 0.3.0, with the unit file, the README, the tests
and the changelog, never mid-release. The prefix stays `LUGH`: it is the project's name in upper case, not
the binary's (the coordinating session, 2026-11-20; Kvasir uses `KVASIR` for kvasir-node the same way).

What each dependant needs of Lugh, and what Lugh needs of Dannan and Dagda, is in `2026-11-20-dependants.md`.

Until Dagda has a switch for its tools (agreed, in its next release), the node build compiles `dagda-migrate` and
`dagda-bench`, and an install carries `dagda-migrate`, its man page and Dagda's library and headers.

Lugh runs as a single-node test service on all four build nodes, each its own genesis; root's password for each is in
`/root/lugh-root-password` there. The service survived the cluster's wipe (2026-11-18; health 200 on all four, checked).
It also rode through node-a's and node-d's unclean power loss (2026-11-20, about 10:20Z): after the restart the service was
active with health 200 on both, its sealed store opened with all its records (1 user, 1 group, 9 audit entries), and the
binary and the dashboard's 32 files checksummed the same as node-b's.

Before Lugh's first release: the fuzz campaigns again, on the instrumented build (P12 plan, "Left for the first release").
Its packaging follows the stack's deb convention (coordinator, 2026-11-20; read Dannan's and Dagda's `debian/` and
`../manannan/docs/packaging.md` first). It uses debhelper (compat 13) from `debian/` driving CMake's install rules, with
`dh_installsystemd` and `dh_installsysusers`, and `tools/build-deb.sh` (Dannan's is the reference layout), built natively on a claimed build node and in CI, lintian clean.
Shared libraries are never bundled: the node links Dannan alone, so the package depends on Dannan's runtime library through
`${shlibs:Depends}`; Dagda (`libdagda-dev`) and Lir (`liblir-dev`, or Lir cloned from the sibling checkout) are build
dependencies of the tests only. A `-dev` range is `>= x.y.z, << next minor~`, its lower bound a full version. The layout:
- `/usr/bin/lugh-node`;
- `/etc/lugh/config.yaml` as a conffile; the secrets in `/etc/lugh/secrets.yaml`, mode 0600, made by postinst and never shipped;
- `/var/lib/lugh` for state;
- `lugh.service` running as the `lugh` user, installed disabled and not started;
- the dashboard at `/usr/share/lugh/dashboard`.

The version comes from `git describe` and must match `project(VERSION)`; an untagged build is `<tree version>+git.g<hash>`, as Dannan's script makes it. A CI job with sanitizers or libFuzzer installs `libclang-rt-19-dev` explicitly, because trixie's clang leaves it out. Packages are `lugh`, plus `lugh-dev` for lugh_client's
headers. The packaging is described in `docs/packaging.md`, while the README covers installation and use.

**The stack's placement plan** (2026-11-20, the maintainer's audits: no duplicated functionality, no special node; agreed by every
session through the coordinator, the coordinator, `../lir-develop-cluster/TODO/2026-11-20-cluster-stack-placement.md`,
"Lugh"). After P8.0: the relying-party work in `lugh_client` (`2026-11-20-client-relying-party.md`, with Lir's and Louhi's calls),
then Lugh's moves onto Dannan's pieces as each lands. Special roles: founding through Dannan's explicit act, POSIX numbers
through an agreement register, the audit exported continuously, single-use OAuth state node-local (the stated exception), and
the readers of `lugh/secrets` from Dagda's catalogue (slice 5). For the maintainer: Q1, an HTTP core in Dannan seeded from Lugh's.

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
- **Dagda's register map, D6** (`../dagda/TODO/2026-11-20-register-map.md`, being built test-first in Dagda's next release):
  `lugh/scope` and `lugh/secrets` become register-map spaces, and `merge::winner` and `merge()` go (`UniqueIndex` stays). Lugh's
  review was taken whole (2026-11-20): tombstone-wins with "never" (the maintainer's "removal over edit, never resurrected"), a put onto a
  tombstone refused, `get_register` for a 410, `changed()` answering each key's before and after for the indexes, and a 64 KiB
  value bound refused at put. Lugh's own bound (`merge::kMostValueBytes`, 256 KiB) drops to 64 KiB at P8.3; the 256 KiB
  tree-node test is no longer needed.
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

## Dependencies pinned

- Dannan **0.9.2** (`LUGH_DANNAN_REF`, a tag in `../dannan`, ABI `libdannan.so.0.9`): agreement with `Outcome::unknown` for P8's
  registers, the listener and connector, `verify_rs256`, the worker pool, the sign-in back-off; 0.9.2 is what Dagda 0.3.x builds
  on. Move the pin when a tag Lugh wants is cut.
- Dagda **0.3.2** (`LUGH_DAGDA_REF`, a tag in `../dagda`, SONAME the whole version), node builds only: slice 1 and
  `Space::covers`. The build nodes need `../dagda/.git/` at `/srv/build/lugh/dagda` beside Dannan's.
- Lir's Lugh plugin pins a `develop` commit of Lugh, and repins at Lugh's first release.

## Builds and tests

No builds or tests on the development workstation, only on the shared arm64 build nodes (the maintainer, 2026-11-14), and no clangd
indexer either (kill this session's after a C++ edit). How to reach the nodes and their claim board is in the gitignored
`CLAUDE.local.md`; real host names and addresses never go in the repository. A job claims only the cores it uses, runs at
`nice -n 19`, and releases its claim when it ends or fails; the tests run only if the build succeeded.

Sanitizers only at a phase's end, for a release, or to hunt a named bug; never for a pin move or another step's gate (the maintainer's rule,
restated 2026-11-17; Lugh's phase-end exception is `CLAUDE.md`'s).

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

- No special-case code for a single node: every project is a leaderless, multi-master soft cluster (the maintainer to the stack,
  2026-11-20).
- Every service's configuration is YAML through `dannan::config` (the maintainer, 2026-11-20); Lugh's is.
- About 100% code coverage on all code (the maintainer, 2026-11-20): measured by `LUGH_COVERAGE` and CI's coverage job to Codecov.
- GoogleTest for all C++ tests; the admin React uses Vitest (the maintainer, 2026-11-20).
- Passwords follow the usual standards: no promise about their characters, ever (the maintainer, 2026-11-20).
- Features and milestones are developed on branches and merged into `develop` when complete, preferably as one squash
  commit for the whole feature or milestone (the maintainer to the stack, 2026-11-20, relayed by the coordinator).

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

Each feature or milestone ends green in debug, ASan with leak detection and TSan, one full run each, on the same code, before
it merges into `develop`. Sanitizers run at that point only, or to diagnose a bug that other methods have not found. Test once:
no repeated runs and no mutation runs unless a change is small or high-risk, and a test that fails at random is investigated,
never tolerated (the maintainer to the stack, 2026-11-20, replacing the 20 repeats of 2026-11-14).

| ID | Phase | State |
|---|---|---|
| P1 to P6 | Skeleton, keys, sealed store, directory and sign-in, the API, OAuth and OIDC | done (P3 frozen until P8) |
| P7 | Dashboard, the React SPA in T.O.M.S's styling; administering through a session needs `phr` | done |
| P8 | The cluster on the stack: Dannan's `Context`, Dagda's spaces, replacing the sealed store and keyring | P8.0 done; the rest waits on Dannan and Dagda |
| P9 | Writable LDAP | done |
| P10 | `lugh_client` | done |
| P11 | WebAuthn, passkeys and `phr` | done |
| P12 | Hardening: fuzzing, the sandbox on real hosts, key rotation drills, the threat model | done; campaigns again before release |
| P13 | SSO rollout: blackraven-admin, T.O.M.S, AthenaSIP admin, Macha; one break-glass account each | not started |
