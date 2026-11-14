# What Lugh needs of Dannan and Dagda

The maintainer, 2026-11-13: Dannan and Dagda must support Macha, Lugh and Lir as first-class citizens, "not as afterthoughts"; that was the
purpose of splitting the technologies out. This is Lugh's side of that: every need, what Lugh does with it, what I found in the
other trees on 2026-11-13, and what would show it works. The stack document (`../dagda/TODO/2026-11-03-stack.md`) is the design;
this is the checklist against it. Status is my reading of the code and capability reports (Dagda `0.1.4`, its report of
2026-11-10; Dannan `0.5.3`, its report of 2026-11-06), for the owning session to correct.

Lugh today keeps everything in its own sealed store, frozen until Dagda carries its spaces (the maintainer: "Keep the store until Dagda"). P8
moves it. What follows is what P8 cannot be done without.

## The shape of Lugh's data

| What | Where | Size, to plan for | Writes |
|---|---|---|---|
| Users, groups, memberships, scope grants, applications, policies, consents | `lugh/scope`, every node a member | 10,000 users, 1,000 groups, 1,000 applications; records under 4 KiB | A few a minute; bursts of hundreds when provisioning over LDAP or the API |
| Password hashes, factors, recovery codes, app passwords, signing keys, refresh-token families, sessions | `lugh/secrets`, Lugh nodes only, others blind at most | As above, plus up to 50,000 live sessions and their refresh families | Sign-in storms: up to 50 commits a second cluster-wide for a minute; steady about 1 a second. A session's last-seen is written at most once a minute |
| Authorisation codes, PAR URIs, device codes, TOTP last-used steps | Node-local, one space per Lugh node | Thousands live; each lives 60 s to 10 min | Tens a second at peak; every one short-lived |
| The audit chain | One per node (node-local, or a head space per node, append-only by Lugh's merge) | Grows for ever, exported | One entry per change and sign-in |
| Published signing keys (JWKS) | A retained value in `lugh/scope` (the maintainer, P6 decision 3), for Lir and others | Under 8 KiB | On rotation, every 90 days |

Every HTTP request and every LDAP operation resolves its caller from memory without waiting; Lugh keeps derived indexes (name,
email, sessions by handle) in memory, rebuilt from the spaces.

## Of Dagda

| # | Need | Why Lugh needs it | Found 2026-11-13 | Would show it |
|---|---|---|---|---|
| G1 | An every-node head space under the domain `lugh/scope` | Scope must be readable on every node that counts toward a write floor | Built: every-node spaces (C10) | A Lugh-shaped space on the neutral owner, three nodes |
| G2 | A space only Lugh nodes can read: `lugh/secrets` | Password hashes and factor secrets must not be readable off Lugh nodes (Decided 6) | **Not built.** `replicas: N` is refused (C9, "L2"); blind replicas and several domains are L8 | A secret written on a Lugh node, held blind (or not held) on a Macha-only node, readable on another Lugh node |
| G3 | The owner's merge, with the common ancestor | Lugh's merge: LWW attributes, versioned credentials, grow-only tombstones, duplicate names resolved deterministically (requirement e) | Built: `Merge::merge(base, heads)` (`heads/space.h:124`) | Two nodes split; both create "alice", one removes a user the other edits; after the merge one alice, the removal stands |
| G4 | A conditional write on one node (Lugh's ETags, Decided 17), in Dannan's shape: deadline, caller's executor, `done` | Every API write is If-Match; the whole of Lugh is callback style | Built: `Context::Heads::mutate` (`context.h:302`) is callback-shaped; corrected by Dagda | A stale version refused, a fresh one taken, completion posted on the caller's executor |
| G5 | The Replicated level with k per space | Credential changes and revocations are Replicated (Decided, Lugh's `ACTIVE.md`); Lugh answers "applied, n nodes pending" from the evidence | **Not built** (L3) | A Replicated write on five nodes with one away: success with that node named pending, then cleared |
| G6 | Reading without waiting, and learning what changed | Lugh's indexes must follow every change on any node: a disabled user stops at once everywhere | `current()` reads nothing (C13); `entries(...)` pages a tree. **A notice when a space's head moves, and the keys that changed between two views, at the cost of what changed?** Not found | A change on node A seen on node B by a notice, with the changed keys, without walking the tree |
| G7 | Node-local spaces, never rolled back | Single-use grants (codes are redeemed once), TOTP steps (a replayed code must fail), the audit chain (requirement b, c, h) | **Not built** (L5, L9) | A code redeemed once survives a crash and is refused the second time; nothing of it leaves the node; an old commit restored is refused |
| G8 | Churn of short-lived records | Grants live 60 s to 10 min; tombstones must go after their window, not grow for ever | Unknown for node-local spaces | Ten thousand grants made and expired; the space stays bounded |
| G9 | Retained values | JWKS in `lugh/scope` for Lir's token checks (P6 decision 3) | **Not built** (L7) | A rotated key seen by a subscriber on another node |
| G10 | Per-origin counters | Sign-in back-off and lockout across nodes; today per node | **Not built** (E10, marked "Lugh's") | Wrong passwords on two nodes counted together |
| G11 | A lease, for single-writer jobs and per user | Only one node rotates signing keys at a time; and every TOTP check holds that user's lease (the maintainer, 2026-11-13), so at sign-in rates | Lease template built (E1 to E9); head-backed leases **not built** (L1) | Two nodes due to rotate; one does |
| G12 | The domain catalogue | `lugh/scope` and `lugh/secrets` made at genesis; `lugh/secrets` wrapped to a node when it advertises `lugh`, and unwrapped when it stops | **Not built** (L8) | A node gains and loses the `lugh` capability and its access follows |
| G13 | The scope check on the write floor | A non-node principal's write decided by Lugh's `ScopeSource` | Built, across replicas: `StoreScope.AnInstalledSourceRefusesOnePrefixOnEveryReplica` | Shown |
| G14 | A multi-node test fixture with Dagda nodes and heads on, stepped time | Lugh's multi-node tests (rule 3: no fixture of Lugh's own) | **Unknown.** Dannan's in-process cluster exists | Lugh's P8 tests written against it |
| G15 | The load above | Every row of the table | Not measured for Lugh's shape | A measurement at the numbers above |

## Of Dannan

| # | Need | Found 2026-11-13 |
|---|---|---|
| N1 | `ScopeSource` and `install_scope_source` | Built (`contract/scope.h:40`, `node_test.cpp:908`). **Question:** which writers carry a non-node principal today? If none, the seam is unexercised outside its test |
| N2 | Node key custody, `derive_local`, for node-local domain keys | Built (`context.h:257`, `node_test.cpp:759`) |
| N3 | CA-signed node revocation, closing sessions at once (requirement f) | Built (`identity/certificate.h:81`) |
| N4 | Placement with the caller's salt, and a call to the owning node that fails closed, for TOTP | Built (`placement::Scheme`, `context.h:128`; `Routes::call` with deadlines) |
| N5 | A `lugh` capability advert | Built (adverts) |
| N6 | Work classes for Argon2id, so hashing cannot starve the node | `sched/` built. **Question:** the class to use, and whether Lugh's own HTTP and LDAP io_context should run on the node's threads |
| N7 | Readiness planes for Lugh's spaces | Built (`Readiness`) |
| N8 | Lugh moves from Dannan 0.4.1 to the 0.5.x Dagda pins | **Question:** anything in 0.4 to 0.5 that changes what Lugh links (crypto, signing, settings reader, percent-encoding) |
| N9 | One Dannan version across the stack (Lir's N4) | Lugh links both libraries, so Dagda's pin is Lugh's; a release train of Dannan, then Dagda, then Lugh and Lir |
| N10 | A partition view, majority or minority side (Lir's N3) | Wanted, not needed for P8: under the accepted partition bound (requirement d) Lugh serves on both sides, but it should say so, in Status and the audit log, rather than count the roster itself |

### Dannan's answers (2026-11-13)

Proposals to the maintainer where marked; nothing changes in Dannan until he rules.

- **N1:** no writer carries a non-node principal; the seam's only exercise is its own one-node test. The cross-node case belongs in
  Dagda, where writes are stored: a directory principal's write decided by the source on the storing replica, refused when the scope
  says no, with the generation as evidence. Dannan would add a two-node test that each node's source decides for calls arriving there
  (if the maintainer agrees). Lugh is to be the seam's first real user.
- **N6:** hashing is foreground work, bounded by memory: reserve each hash's `memory_kib` through `Context::budget().reserve(foreground)`
  first and answer "try later" at once when there is no room, so a storm costs at most the foreground budget. Hash on Lugh's own
  worker threads registered with `Context::threads()`, never the node's executor. Gap: Dannan admits by memory, not CPU; Dagda has
  Macha's CPU pacing. **Proposal to the maintainer:** a class-aware worker pool with CPU pacing moves into Dannan. Listeners: Lugh keeps its own
  io_context for HTTPS and LDAP for now. **Proposal to the maintainer:** a shared public listener in Dannan (accept and per-source limits, TLS),
  since Lir needs MQTT listeners and AthenaSIP SIP. This touches the maintainer's decision 9 ("HTTP stays each hosted system's own"): Lugh's
  view is below.
- **N8:** nothing Lugh links changed from 0.4.1 to 0.5.6 (identity, signing, Argon2, custody, config and encoding identical); `context.h`
  only gains. To know: a call is watched for progress only if it asks, and call deadlines follow injected time.
- **Alpine:** passes on amd64 with no source change (2026-11-13: Alpine 3.24.2, musl, GCC 15.2.0, Alpine's own Boost, OpenSSL, yaml-cpp
  and GoogleTest; 646 passed, 1 skipped as root, as on Debian). arm64 not shown: emulation misreports `posix_spawn`, so Dannan proposes
  an Alpine step in hosted CI on both architectures. Raven runs on the arm64 build node (the maintainer's Alpine commit `aaac977` seals under its OTP key),
  so arm64 is the proof Lugh waits for.
- **N9:** **proposal to the maintainer:** patch releases keep the ABI (abidiff in CI), SONAME at major.minor, so any 0.5.x patch loads under one
  Dagda tag. Until then, pin the Dannan the Dagda tag was built on.
- **N10:** one reading on `Nodes`, measured against the roster as last agreed (shrunk only by an operator's retire, never by absence),
  so neither side of a split calls itself the majority.

**What a shared listener must cover for Lugh**, sent to Dannan: an operator-provided certificate and key per listener (browsers and
LDAP clients check a public name, not the cluster CA), TLS 1.3 only; a second listener that asks for client certificates against a
configured CA and hands the certificate's subject and thumbprint up (mTLS, RFC 8705); a plaintext listener whose connection upgrades
to TLS in place on the hosted system's word (LDAP StartTLS), with nothing read past the upgrade request until the handshake; the peer
address, and trusted proxies' X-Forwarded-For for HTTP; per-address limits before a credential and per-caller limits after, shared
across listeners; connection caps and idle and handshake deadlines per listener; and a stop that closes what is open. The protocol
(HTTP, LDAP) stays Lugh's, as the maintainer decided; a shared accept-and-TLS layer under it is welcome if it covers the above.

Dannan agreed (2026-11-13): the proposal is only that layer, so Decided 9 holds; the nine points are its requirements. Limits
after a credential are a shared object Lugh charges and the listener consults at accept. Ports come from an inherited socket when
one is given (systemd), otherwise bound with `CAP_NET_BIND_SERVICE` (OpenRC, Raven).

### Dagda's design, and Lugh's review (2026-11-13)

Dagda answered with one design for Macha, Lugh and Lir: `../dagda/TODO/2026-11-13-three-systems-design.md`, in slices, going to
The maintainer after Lugh and Lir review it. Its corrections, checked in the code: G4 is built (`Context::Heads::mutate`, `context.h:302`, takes a
deadline, executor and `done`), and so is G13 across replicas (`StoreScope.AnInstalledSourceRefusesOnePrefixOnEveryReplica`,
`store_scope_test.cpp:124`; claims at `:179`). Slice 1 (node-local spaces, the change notice, the installed fixture) lets P8 start.

Where Lugh found it short, sent to Dagda:

1. Placement is not confidentiality: `lugh/secrets` needs a domain key only Lugh nodes hold in slice 2, not slice 5's catalogue.
2. Every Lugh node must hold `lugh/secrets`, not N of them: callers are resolved from memory on whichever node a client reached.
3. The audit log never drops an entry: an entry goes only on export's acknowledgement; at the bound an append is refused; no rollback.
4. The per-origin counter must forget: slots expire after the owner's window, or a locked account stays locked.
5. The rate measurement includes Lugh's shape, and the time from a commit on A to `watch` and `changed` on B.
6. A named churn case for node-local spaces, with numbers.
7. Each slice's tag keeps what the last gave, since Lugh builds on slices before v2 is frozen.

Lugh agrees with the design's five questions for the maintainer.

Dagda took all seven into the draft, each with a case (checked 2026-11-13): slice 2 opens `lugh/secrets` under a domain whose key is
wrapped only to configured members, with a new `capable(capability)` policy so every Lugh node holds it; an audit log refuses at its
bound and goes only by `retire` on export, with no rollback; the counter map forgets after the owner's window; Lugh's shape is in the
measurement; the churn case is named; each slice tag keeps what the last gave or says what changed. Lir's review moved the v2 freeze
to slice 4 and put the catalogue in v3. Lugh has nothing else short; one stale sentence (placement read as meeting G2) was sent back.
For the operator until slice 5: a node newly advertising `lugh` holds `lugh/secrets` but cannot open it until configuration names it a
member, so sign-in fails there until then.

## Ruled (the maintainer, 2026-11-13)

- **Dagda's three-systems design, all as proposed** (Dagda `a058df9`, "Ruled"): logs a Dagda noun; the register-map merge (carrying
  the JWKS) and the counter map with forgetting slots; the advert aggregate in Dagda; slice 0 first, then slices 1 to 5; contract v1
  frozen at `0.1.4`, v2 at slice 4, the catalogue as v3; the 10-minute tombstone window for Lir's QoS 2 as a stated limit. From
  Macha's review, `0.1.5` (Dannan 0.5.7, the ABI-promise release, and the Debian packages) leads slice 0. P8 starts on slice 1.
- **Dannan's proposals** (`../dannan/TODO/2026-11-13-stack-needs.md`): the ABI promise (`libdannan.so.0.5`, SameMinorVersion,
  abidiff in CI); the partition reading (an even split is a minority; joins add to the agreed roster, only a retire removes); the
  shared listener below the protocols with Lugh's nine requirements; CPU admission in a class-aware pool. Dannan's order: the ABI
  promise, Macha's items, the partition reading, CPU admission, the listener.
- **Alpine, not now**, for Dannan and Dagda alike; and Raven is dropped from all of Lugh's development for now (the maintainer, 2026-11-13).
- **TOTP replay under a per-user Dagda lease** (the maintainer, 2026-11-13), not the owning node's node-local space: leases are then on the sign-in path, at sign-in rates (told to Dagda). Dagda: one lease space keyed by user; an acquire is one replicated commit, so it is in slice 0's measurement (50 a second over 10,000 keys, p50 and p99). Consequence, stated: during a split a node that cannot reach the lease space's replicas cannot grant the lease, so a TOTP sign-in on that side fails closed ("try again shortly") rather than risk a replay. Recovery codes are single-use too and take the same lease. Accepted by the maintainer (2026-11-13).

## Slice 0's first figures for Lugh's shape (Dagda, 2026-11-14, Mac, today's head path)

Three in-process nodes, one every-node space of 50,000 keys, one writer: 37 commits a second reached of 50 wanted (commit p50
18 ms, p99 102 ms); a commit on A seen on B at p50 103 ms, p99 347 ms, max 484 ms. So "disabled on A, refused on B" is about a
tenth of a second, and a TOTP lease about 120 ms typical, 450 ms worst: both fine. Correction sent: a TOTP sign-in is about
three head commits (the session, the lease acquired and released), so a 50-a-second storm is about 150 commits a second, and may
land on one node; asked whether concurrent `mutate`s on one node group-commit, and for that measured, before P8.5. The build node run is
the firmer figure.

Dagda's answer: commits to one space are serialised (its mutation lock is held across the local commit and device writes), and
a node reaches about 100 to 200 head commits a second in all on the Mac, whatever the number of spaces. Lugh's own cuts, taken
regardless: the TOTP step and the session in one `lugh/secrets` commit, and the lease left to lapse after a second or two
rather than released, so a TOTP sign-in is two commits (about 100 a second in a storm). Lugh prefers group commit for heads in
Dagda, which Lir needs too; Dagda puts both options to the maintainer. Figures for 1, 4 and 8 writers on one node to follow.

## Of both

- **Alpine (musl, GCC 15)** for Raven: every project must build and pass there. Has either been built on Alpine?
- **Evidence, not booleans**: each of the above shown by a named case, as the capability reports do for Macha.

## Order

Dagda's plan put every Lugh item (its L1 to L9) after Macha's port. Under the maintainer's ruling they are not afterthoughts. What Lugh asks
for is a plan, from the Dagda session, that carries G2, G4 to G12 and G14 alongside Macha's work, and the date each lands, so P8
can start on the first of them rather than waiting for all.
