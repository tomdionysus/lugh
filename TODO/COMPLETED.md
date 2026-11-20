# Complete

What shipped, newest first, with the date and why.

## 2026-11-20: lugh_client for relying parties, and the topic-scope grammar moved into it

The stack's placement plan (the maintainer: the lower of two projects that depend on each other keeps what both need): what Louhi and Lir
had each written for themselves is lugh_client's (`2026-11-20-client-relying-party.md`, `2026-11-20-dependants.md`).
`discover()`; `bearer_token()` (16 KiB, Louhi's bound); `RelyingParty` (the verifier, the key source and the audience);
`TokenSource` (a service's client-credentials token, refreshed at two thirds of its life, failing over across issuers with a
back-off that never parks); `testing::FakeHttps`, thread-safe, holding a request until the test answers. The topic-scope
grammar moved from the node into lugh_client (`lugh/client/scopes.h`), with `TopicGrants::parse` for brokers; lugh-node grants
by the same code, and `printable` moved into `lugh/core/encoding.h`. The PUBLISH and SUBSCRIBE checks follow on `lir::mqtt`.
Found on the way: TokenSource fetched on any timer wake, but a stepped time source wakes early by design; and an OAuth test
read begin() and end() of two copies. Tests: 829, from 814 (fifteen new, none removed). Debug, ASan and TSan on node-a with
the real-LDAP-client branch, once each: green, no sanitizer report.

## 2026-11-20: P8.0, Dagda beside Dannan, and the cluster rig

The maintainer's word to start P8, on Dagda 0.3.2 and Dannan 0.9.2. Dannan moves to 0.9.2, the patch Dagda 0.3.x builds on, declared with
`OVERRIDE_FIND_PACKAGE` so Dagda's `find_package(dannan)` takes the fetched one; Dagda is fetched from the sibling checkout at
its tag, for node builds only. `ClusterRig` opens `lugh/scope` and `lugh/secrets` on Dagda's in-process cluster, one node or
three, the first founding and the rest joining, maintenance on as a deployed node runs it. Found on the way: `Heads::current()`
reads nothing, so it answers an empty view after founding, a restart or a peer's commit (the rig reads with `HeadRead::local`);
and a node that missed a commit is brought up to date by its maintenance, not by the change notice. Tests: 814, from 809 (five
new, none removed). Debug, ASan (clang 19) and TSan (clang 19) on node-a, once each: green, no sanitizer report.

## 2026-11-17: the CBOR decoder's counts bounded

The hour-long fuzz campaign (twelve targets an hour each, about 3.4 billion inputs, nothing found) ended with `fuzz_webauthn` out
of memory, and that led to a real bound: an array or map header was checked only against the bytes left, so the decoder made a
Value for every claimed item before reading one, at every level of nesting, and a few kilobytes of attestation object could make
tens of megabytes. A count is now held to the items `kMostItems` still allows. Tests: 809 (one new). Debug on node-c, ASan on
node-c, TSan on node-a: green, no sanitizer report. Still open: `fuzz_webauthn`'s RSS climbs under ASan with the bound in place
while its live heap stays small (`2026-11-16-p12-hardening.md`, "Open").

## 2026-11-16: P12, hardening

Plan: `2026-11-16-p12-hardening.md`. The maintainer's rulings: an app password with any scope beyond `lugh:directory.read` needs a phr
session; the dashboard's CSP keeps its inline scripts by hash; the test install goes on every build node ("Lugh is a cluster. Install
on all of them, as a test").
- **Fuzzing (H1, H2)**: the libFuzzer check never passed (it linked a main of its own), so no target had ever built; it now
  builds an entry point, and all 13 targets build with clang 19, `fuzz_client` and `fuzz_webauthn` among them. Seeds for the six
  text targets; `lugh/fuzz/campaign.sh`. The first campaign (10 minutes a target) found two things: `encode_topic` wrote `"` and
  `\` literally, making a scope that was no scope (fixed, with a test), and `fuzz_records` held an old-format record to its bytes
  (its property fixed). Targets now abort rather than trap, since SIGTRAP left no input. The second campaign: about 650 million
  inputs, nothing found. Hour-long campaigns remain.
- **The sandbox (H3)**: Lugh installed by `cmake --install` as a service on all four build nodes, each its own genesis until P8. On each:
  `systemd-analyze security` 1.4 (OK); `LoadCredentialEncrypted=`, `LimitMEMLOCK` and `MADV_DONTDUMP` proved on Linux for the
  first time. Found: GCC 14's release build stopped on a false "maybe uninitialized" (rewritten), and the install never ran
  `ldconfig`, so the node could not find Dannan's library on a clean host (it does now). Root's password for each is in
  `/root/lugh-root-password` there, root only.
- **Key rotation drill (H4)** on the real binary: tokens issued before a rotation verify after it, and after a restart.
- **The threat model (H5)**: `docs/threat-model.md`.
- **Also**: app passwords at phr for any administering scope; Dannan 0.8.5 pinned, its `Backoff` used and Lugh's deleted (Kvasir's
  ask, so the two link one copy). The process tests now give their nodes an empty config, since a host running Lugh has an
  installed one its service alone may read.

Tests: 808, from 810 at P7: plus the app password rule 1, the topic scope's quote 1, the rotation drill 1; minus the five
`Backoff` tests, which moved with the class to Dannan (`dannan/test/listen_backoff_test.cpp`). Debug on node-d, ASan on node-c,
TSan on node-a (all on the 4K-page, 48-bit-VA kernel): green, no sanitizer report, on the final code; the rotation drill
repeated 20 times in each.

## 2026-11-16: P7, the dashboard

Plan and rulings: `2026-11-16-p7-dashboard.md`. The maintainer, 2026-11-16: phr is enforced on the server for administering, and root's
first sign-in is offered a passkey and TOTP both.
- **The phr gate**: `http::Caller` says whether it came through a session; the router refuses a scoped route to a session below phr
  with `403 phr_required`. `/api/v1/me/*` stays open at mfa, so a person adds their first passkey there; tokens are unaffected.
- **Root's passkey**: root's first sign-in was already offered one; proved on the real binary, and the process tests that
  administer through a session now enrol root with a passkey (`RootBrowser::sign_in_and_enrol_passkey`).
- **The static site** (`lugh/http/static_site`): `static.directory` read once at start into memory (4096 files, 64 MiB at most),
  links and dot-files left out; SPA routes get `index.html`, a missing file a JSON 404; `assets/` immutable, the rest revalidated
  by ETag; each page's CSP allows this origin and its inline scripts by hash (a departure, for the maintainer). A directory that cannot serve
  stops the start. `cmake --install` copies `dashboard/build/client`, refusing a missing build; the unit passes `--static-directory`.
- **The dashboard** (`dashboard/`): React 19, React Router 7 (SPA), Vite 7, TypeScript 5.9, T.O.M.S's tokens. The account
  (factors behind the re-authentication window, sessions, password, app passwords), users, groups (members, scopes with a diff),
  policies, applications, keys and the audit log; its own confirmation dialog. Sign-in and step-up through
  `/signin?continue=dashboard[&acr=phr]`, a fixed word that comes back to `/`. A TOTP setup's answer carries its QR modules.
- **Found on the way**: the group members route answers `{members}` (the client read `{users}`; Playwright found it). The store's
  concurrent-writer test destroyed an `io_context` another thread could still be posting to (TSan, once in a full run): each
  writer's context now outlives every writer. node-b's new 4K-page kernel (39-bit VMA) stops g++'s ASan from starting at all, so
  Lugh's ASan is now clang 19 (`build-asan-clang`).
- **Asked of the maintainer**: the CSP departure; whether an app password with an administering scope needs a phr session (recommended).

Tests: 810 in `lugh_tests`, from 799; 11 new, none removed (the router's gate 1, the static site 5, the dashboard on the real node
3, root's passkey 1, the sign-in's way back 1). Debug on node-b, TSan on node-a (clang 19): green, no warning, on the final code.
ASan with leak detection: 810, green, no sanitizer report, on node-b back on the 16K kernel (GCC; the 4K-page kernels' 39-bit
VMA stops ASan starting under g++ or clang, so P7 merged first and ran it after, at the maintainer's word). Its stale precompiled headers
crashed GCC after the kernel change and were removed. The new process tests repeated 20 times in TSan and ASan, and the store test 20 times in TSan. The dashboard: Vitest
15, and Playwright 5 on a real `lugh-node` on node-b (root's first sign-in with Chromium's virtual authenticator, a user, a group,
the account and the audit chain, and root back with the passkey alone).

## 2026-11-16: a person's own factors, and HttpsClient on Dannan's connector

A person's own factors (`2026-11-15-self-factors.md`), on the maintainer's rulings of 2026-11-15:
- `/api/v1/me/factors` (`lugh/api/factor_routes`), from the person's own session only: list, add a TOTP factor (shown once, then
  confirmed with a code), add a passkey, rename a passkey, remove a factor under the last-factor rule, and new recovery codes.
- Every change needs the session's re-authentication window (`session::Reauthentications`): ten minutes, by sid, in memory, so a
  restart closes it. `Authenticator::reauthenticate_totp` and `reauthenticate_webauthn` open it, with the sign-in's back-off and
  audit (`reauth.*`). Never the password alone, never a recovery code; a code is refused where the policy is phr.
- `Factors::webauthn_rename`. The pages and these routes share one set of WebAuthn challenges, bound here to the session's sid.
- Notifying the person of a change waits on principal events over Lir.
- Found on the way: `factor_key` refused a `webauthn-` ID, so an administrator could not remove a passkey by its listed ID. Fixed.

`HttpsClient` (`lugh/client/https.cpp`) now connects through Dannan 0.8.3's `StreamConnector`, its face and tests kept. The roots
and the client certificate are read once at construction; an empty CA path reads the system's bundle file. Louhi, which links
lugh_client, was told what changes for it and is unaffected.

Tests: 799, from 784; 15 new, none removed (the window 3, the authenticator 1, the routes 9, a process test on the real
`lugh-node` 1, an HTTPS port test 1). Debug and ASan with leak detection on node-b, TSan on node-a (clang 19): one
run each, all green, no sanitizer report. The new tests repeated 20 times in each build, with the HTTPS tests, all green.

## 2026-11-15: P11, WebAuthn, passkeys and the phr level

Plan and rulings: `2026-11-15-p11-webauthn.md`. The maintainer ruled P11 before the dashboard (P7). The other rulings:
- attestation is `none`;
- RS256 verification goes in Dannan, and CBOR and COSE in Lugh;
- RS256 is accepted at 2048 bits and up;
- passwordless sign-in is offered to everyone.

What was built:
- W1: CBOR (strict, canonical, bounded) and COSE keys for ES256, EdDSA and RS256, with a fuzz target. The UTF-8 check moved into
  `core/encoding.h`, and jose gained `public_key_der()`, so both are kept once.
- W2: the registration and assertion checks of WebAuthn Level 3, sections 7.1 and 7.2. The software authenticator in
  `lugh/test/fixtures/soft_authenticator.h` is written from the specification, apart from `lugh/webauthn`.
- W3: WebAuthn credentials in `Factors`. A credential id registered to anyone is refused, and the sign count is written at the
  version read. A credential counts as a second factor, and as the last one.
- W4: the authenticator's steps:
  - a credential as the second factor (with the password, `phr`);
  - a passkey alone (user verified, `phr`, refused the same way whatever is wrong);
  - enrolment by a credential.
  `authn::Challenges` holds nothing when it issues a challenge: random bytes and an expiry, MAC'd under the process's key and
  bound to the visitor's cookie. A challenge is single use, claimed then released if the ceremony fails, and refused when the
  used set is full. The pages gain one first-party script, the options as JSON, and the result as a form. WebAuthn is offered
  only with `oauth.issuer`, whose host is the RP ID.
- W5: applications and `acr_values` may require `phr`. The level wanted rides with the sign-in, which only raises what it
  requires, and at `phr` only the key is asked for (TOTP and recovery codes are refused).
- W6: `Caller` carries its `acr`, and an administrator's factor reset requires `phr` (a service acts with its key). Root's
  first sign-in enrolling WebAuthn is deferred to P7 (the maintainer).
- W7: on the real binary over TLS, a passkey is enrolled through a link, signs in alone, and outlives a restart; a cloned
  authenticator and another origin are refused.
- Dannan 0.8.3 (verify_rs256, the stream connector) pinned; RS256 assertions verified.

Tests and checks:
- 784 tests, from 725 at P11's start: 59 new, none removed.
- Debug on node-d and node-b.
- ASan with leak detection on node-b: green, no sanitizer report.
- TSan on node-a (clang 19): green, no warning.
- The new process, sign-in and challenge tests were repeated 20 times in debug, ASan and TSan, all green.
- Found by clang: CBOR's `std::vector<std::pair<Value, Value>>` inside `Value` would not compile with libstdc++, so it became a
  declared `Value::Entry`. TSan, debug and ASan with leak detection were each run once more on the change: 784, green,
  no sanitizer report.

Left for later:
- adding a key after enrolment (`/signin/factors`);
- the fuzz targets built on node-a's clang (`fuzz_webauthn` and `fuzz_client`, both written, both unbuilt);
- root's enrolment at P7.

## 2026-11-15: step E, ClientAddress on Dannan's forwarded_for

- `ClientAddress` keeps its face (`resolve(peer, request)`). Its own walk of X-Forwarded-For is deleted, and it calls `dannan::listen::forwarded_for()` with the trusted networks as `Prefix`es. Several header lines are joined in order (RFC 9110 5.3).
- Changes in behaviour, each with a test:
  - A chain of trusted proxies is now walked back to the first address that is not one. Before, the last entry was taken even when it was another of the operator's proxies.
  - A chain made only of trusted proxies resolves to its first entry.
  - `addr:port` and `[v6]` entries are read.
  - An entry that is not an address stops the walk at the trusted proxy before it, never past it.
- The comments in `config/config.yaml` and `lugh/node/config.h` now say so.
- 725 tests (721 plus 4). One run each: debug and ASan with leak detection on node-b, TSan on node-a. All green, no sanitizer report. The new tests are pure functions with no threads, so they were not repeated.

## 2026-11-15: the listeners on dannan::listen, steps A to D, on Dannan 0.8.2

On `feature/dannan-listen`, not yet merged.
- A: `HttpServer` (HTTPS and mTLS) accepts through `dannan::listen::StreamListener` and takes a `listen::Certificates`.
- B: `LdapServer` does the same, with StartTLS through `Stream::start_tls`. The LDAP StartTLS tests passed unchanged.
- C: `lugh-node` builds one `Certificates` per listener's files and reloads them on SIGHUP. `deploy/lugh.service` gains `ExecReload`. A new process test covers this, `NodeProcess.SighupReloadsTheCertificates`. Socket activation is deferred, with the reason in `2026-11-15-dannan-0.8.md`.
- D: `TlsContext` is deleted (`lugh/http/tls_context.{h,cpp}`), and nothing in Lugh used it after A to C.
  - Its 5 tests went with it: `LoadsAMatchingPair`, `BothPathsAreRequired`, `AMissingFileIsNamed`, `AKeyThatDoesNotMatchTheCertificateIsRefusedAtStart` and `SomethingThatIsNotAPemIsRefused`.
  - Why: they tested a class that no longer exists. What they proved is now proved elsewhere:
    - Dannan's own `Certificates` tests.
    - `node_config_test`, which already refuses empty TLS paths.
    - Every TLS test, all of which load a matching pair.
    - A new process test on the real binary, `NodeProcess.StartRefusesCertificatesThatWillNotServe`: a mismatched key, a key that is not PEM, and a missing key each stop `lugh-node`. Each error names the file and never logs a key.
- The pin moves from 0.8.0 to Dannan 0.8.2.
  - 0.8.1 fixes the hang Lugh found in `stop_accepting()` and sets TCP_NODELAY on accepted sockets.
  - 0.8.2 carries Lugh's finding: a key that did not match its certificate was reported as "not a PEM private key"; it now says "not the key of" the chain (7dce5e3). An encrypted key is refused without ever asking for a passphrase (1899262). Lugh reviewed both.
  - Lugh's process test asserts the mismatch wording.
- Test count: 721, down from 725 (minus the 5, plus the 1). On 0.8.1, debug and ASan were already green.
  - On 0.8.2, the phase checks: debug and ASan with leak detection on node-b, TSan on node-a. One run each, 721 tests, all green, no sanitizer report.
  - The new process test was not repeated. It runs `lugh-node` to its end three times and has no thread or timing race of its own.

## 2026-11-14: P10 done, lugh_client

- P10.3a to P10.3d: `OAuthClient` (code with PKCE and PAR, the return checked for issuer, state and error, the ID token verified with its nonce, refresh, client credentials, the device flow, DPoP proofs, `tls_client_auth` and the mTLS aliases); client authentication `none`, `private_key_jwt`, `client_secret_basic`, `tls_client_auth`; `HttpsClient` presents a client certificate.
- P10.4: introspection and revocation. P10.5: `ApiClient` over `/api/v1` (Bearer or DPoP, If-Match, the API's codes as faults); `Https` with PATCH, PUT, DELETE and ETags.
- As Lir asked: `AccessToken::x5t` as its 32 bytes, refusing a malformed one; `lugh/client/testing.h` for consumers' tests.
- P10.6: the end-to-end test against the real `lugh-node` (keys by discovery, client credentials, offline verification, the API, introspection, revocation); `docs/client.md`.
- Found on the way: Lugh's own `base64` encoder was missing (added); the process tests' `Serving` takes a port chosen first; two test fixtures fixed (a device poll stepped before its answer arrived, an mTLS server not told it was one), and the flow test's 43-letter thumbprints replaced by real ones.
- 724 tests (from 666 at P10's start, 58 new, two moved). Debug on node-d; the phase's ASan with leak detection (node-b) and TSan (node-a, clang 19), one run each, all green, no sanitizer report; every new threaded, timing or network test repeated 20 to 50 times in debug, ASan and TSan.
- Merged into `develop` for Lir to repin (Lir's Lugh plugin, 9452fd0, is on 2b60b52).

## 2026-11-14: P10.1 and P10.2, the Verifier and the HTTPS key source

- `lugh::client::Verifier` (public, `lugh/include/lugh/client/verifier.h`, `tokens.h`): several trusted issuers with their own keys from a JWKS; `iss` picks the keys, `kid` the key; refusals a key source acts on; ID tokens checked as OIDC Core 3.1.3.7 has a client check them; an injected wall clock; keys replaced under a lock while tokens are checked; a hint naming the issuer when a token is refused for missing keys.
- `lugh::client::Https` (public): GET and POST with headers and a body, answering the status, type, caching and a 64 KiB-bounded body; certificate and name always verified, no redirect followed. The node's back-channel posts ride it, and the node's own copy went.
- `lugh::client::HttpsKeySource` (public): discovery (its issuer the one asked for, an https `jwks_uri`) then the JWKS; at start, hourly, and on the verifier's hint at most once a minute per issuer; a failure keeps the keys and backs off 5 s doubling to 5 min; each issuer's state visible; `refresh_now()` the operator's action; timers on a strand by an injected `TimeSource`.
- 693 tests (19 new: 8 verifier, 4 HTTPS, 7 key source; the two URL tests moved, not added), one debug run on node-b. The new threaded and timing tests were repeated 20 to 50 times each in debug, ASan with leak detection and TSan (node-a, clang 19): all green, no sanitizer report.
- Found on the way: Lir's `TokenVerifier` passed steady time where a token's lifetime is wall time; Lir changed its seam (Lir 8d78c95). Lir keeps a stricter rule than Lugh's skew at `exp`, stated in Lir.

## 2026-11-14: P10.0, the lugh_client library

- `jose` moved to `lugh/client/` as `lugh::client`; Boost.JSON's definitions moved there too (the maintainer: `lugh_client` carries them).
- `lugh_client`, a static library exported as `lugh::client`, linked by the node's `lugh`; `LUGH_BUILD_NODE=OFF` builds it alone (configured and built on a build node); Lugh fetches Dannan only when the build has no `dannan::dannan`, so a consumer keeps one Dannan.
- `check_access_token`: RFC 9068's offline checks, answering the token or why not; `TokenIssuer::verify` calls it and adds opaque handles and revoked jtis.
- 674 tests (8 new, `client_access_token_test.cpp`), one debug run on node-b. The package config waits for a release.

## 2026-11-14: Dannan 0.7.0

- Pinned to Dannan 0.7.0 (the partition reading, the deferred reply; `libdannan.so.0.7`). Nothing Lugh uses changed. 666 tests, unchanged, one debug run on node-b. The reading goes into Status and the audit log with P8.1.

## 2026-11-14: Linux pass green: debug, ASan with leaks, TSan; Dannan 0.6.0

- Pinned to Dannan 0.6.0, with Boost's floor at 1.83 (Debian 13's).
- LeakSanitizer (on by default on Linux, off on macOS) found cycles left at exit, now broken: `AsyncMutex::abandon`, `SealedStore::abandon_waiters` and `AuditLog::abandon_pending`, called by `lugh-node` once its threads are joined (waiting coroutines held the store that held them); `Directory` holds its dependents weakly (`AppPasswords` holds the `Directory`; every dependent is kept by its owner, so a removal still reaches all of them); `TestPoolJoin` joins the test pool before exit (OpenSSL's per-thread state).
- TSan on node-a (set up today as the stack's TSan build node: clang 19, 4K-page kernel) found three reports, all one false positive in Boost 1.83's Asio: `any_executor`'s shared target drops its last reference with a release decrement and a standalone acquire fence, which TSan does not model. Suppressed for that destructor only, in `lugh_tests`' TSan build (`lugh/test/tsan_suppressions.cpp`).
- 666 tests, unchanged: one run each in debug (node-b, GCC 14), ASan and UBSan with leak detection (node-b), TSan (node-a, clang 19); all green. One run each, per the maintainer's rule of 2026-11-14 on repeated runs.

## 2026-11-14: TODO rationalised; orphaned test nodes fixed in Dannan 0.6.0

- `ACTIVE.md` cut to what is live: the uncommitted work, the TSan build node, the cluster's rules, what waits, the documents and the plan with each phase's state. Moved out as history: the alignment narrative, Dannan's 0.4.0 foundations and percent-encoding (recorded below, 2026-11-04), and the dated "For P6/P8 from Dannan, Dagda and Lir" notes, whose substance is in the P8 plan and the needs document.
- Confirmed by the maintainer (2026-11-13), all as built: a session's scopes re-read within a minute; CSRF only on requests that may change something; role mapping in the ID token and userinfo, not access tokens; an application with no audiences gets its `client_id` as `aud`; mTLS on its own optional listener; back-channel logouts waiting and opaque-token state in memory until P8; leaving after a form by a page, not a 303; everyone bound may search from LDAP's fixed containers; a `pwd`-policy person binds with their main password with a factor enrolled; HTTP's rate limits apply to LDAP.
- Orphaned `lugh-node` processes after a crashed or killed `lugh_tests` (the maintainer, 2026-11-13: fix it): fixed in Dannan's `ChildProcess` with a reaper per child (other descriptors closed, exit seen with `waitid(..., WNOWAIT)`, `pipe2(O_CLOEXEC)` on Linux, the residual pid-reuse window stated), shown under ASan and TSan; released as Dannan 0.6.0 (not 0.5.7: 0.5.4 had broken `libdannan.so.0.5`'s ABI). Lugh's pin moves to it in the next commit.

## 2026-11-14: Lugh on Linux, first build and run

- The first build of Lugh on Linux: Debian 13 arm64, GCC 14, on the shared arm64 build node node-b, with Dannan 0.6.0 (the pin is the next commit, since Dannan 0.4.1 needs Boost 1.87 and Debian has 1.83). GCC's `-Wshadow` is stricter than clang's (a local shadowing an enclosing lambda's local, or a namespace name such as `http::status`), and `-Werror` made each fatal; it also asks for braces round an assertion under an `if` (`-Wdangling-else`) and every member of a designated initialiser. All fixed by renames and braces, no behaviour changed: 16 files.
- 666 of 666 pass there, plain; ASan on node-b is in hand. The same 666 pass on the Mac.

## 2026-11-14: P8's merge, ahead of Dagda's slices

- `lugh/merge/record_merge.h`: the merge the maintainer ruled for Lugh's shared spaces (P8 plan, "The merge"), as pure functions: the record envelope (version, writing node, tombstone) and its codec, `winner` (a removal over any edit; then the higher version, then the higher writer), `merge` over any number of heads, commutative, associative and idempotent; `writable` (a removed key never again); and `UniqueIndex`, which keeps two records of one name and reports the name ambiguous. Ready for Dagda's `Merge` at slice 1. Fuzz target `fuzz_envelope`, syntax-checked only.
- Tests: 658 to 666, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-06: `ldap.anonymous_bind`, and LDAP driven by a current client

- `ldap.anonymous_bind` (the maintainer, 2026-11-06), default false. On, a bind with no name and no password succeeds on either listener and leaves the connection anonymous, reading the rootDSE and nothing else; a bound connection that does it gives up its identity. A name with an empty password stays refused, whatever the setting. It amends the plan's `BindRequest` row.
- OpenLDAP 2.6.13's tools against a real `lugh-node`, doing their own TLS 1.3 with the certificate checked, over LDAPS and over StartTLS: the same forty cases as Apple's 2.4.28, and the same answers on both, apart from allocated numbers and the order of `member` values, which has none. Main-password binds and `ldappasswd` too. With the setting on, a stock `ldapsearch -x` reads the rootDSE, including over plaintext.
- For clients: OpenLDAP's library swaps the name `localhost` for the machine's hostname before checking the certificate, so it fails on a certificate naming only `localhost`. Not Lugh's, noted in `docs/ldap.md`.
- Tests: 652 to 658, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-05: LDAP driven with real clients

- Apple's OpenLDAP 2.4.28 tools (`ldapsearch`, `ldapwhoami`, `ldapadd`, `ldapmodify`, `ldapmodrdn`, `ldapcompare`, `ldapdelete`, `ldappasswd`) against a real `lugh-node`: binds, the whole tree, PAM-style lookups, filters, paging, limits, compare, add, modify, rename, delete, the Assertion control, critical controls refused, and Password Modify, which ended the person's session. All answered as `docs/ldap.md` says, with no secret in the log.
- Those tools cannot do TLS 1.3, so they went through a scratch stunnel-style shim, not committed. `openssl s_client` tested Lugh's TLS directly: LDAPS and StartTLS on 1.3 verify, and 1.2 is refused. So no one client has done LDAP operations over its own TLS 1.3. A current OpenLDAP could not be built here: running downloaded code was refused by the session's permissions.
- Found: a stock `ldapsearch -x` with no `-D` is refused at its anonymous bind and stops. Waiting on the maintainer (`ACTIVE.md`). No test added or changed.

## 2026-11-05: The sign-in's back-off on changing a password

- `/api/v1/me/password` checked the current password with only the router's caller limit, 600 a minute, so a stolen session was a fast way to guess it. It now goes through the authenticator: back-off shared with the sign-in, `429` with `Retry-After` while waiting, and audited.
- Tests: 651 to 652, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-05: LDAP step L5b, POSIX numbers; LDAP complete

- `lugh/directory/posix_numbers.h`: a counter per range in a new `counters` table, advanced by compare-and-set, so a number is never shared or given twice, whatever becomes of its holder. A person or group gets one when made; a service spends none, since it cannot have a `posixAccount`. `POST /api/v1/ldap/posix/allocate` numbers what came before, in creation order, in one audited pass. `ldap.posix.*`, all three required together, and root's own number shown over LDAP on the real binary.
- A range used up refuses the creation. A number taken for a creation that then fails is spent, not reused.
- `docs/ldap.md` written, and `docs/architecture.md`, `docs/api.md` and `ACTIVE.md` brought up to date.
- Tests: 636 to 651, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-05: LDAP step L5a, the writes

- `lugh/ldap/writes.h`: add, modify, delete and rename as the API makes them, so the rules, versions and audit are the same, the actor the bound user and the source `ldap:<address>`. The Assertion control (RFC 4528), with `(lughEntryVersion=<n>)` as `If-Match`. A user's modify is one update, failing entire; a group's changes attributes or members, never both, and a member that names nobody changes nothing. Deleting a user ends their sessions at once, as the API does.
- Password Modify (RFC 3062): the bound user's own, only after a main-password bind, with the old one given and through the sign-in's back-off; every session of theirs ends.
- Tests: 612 to 636, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-05: LDAP step L4b, the listeners

- `lugh/ldap/connection.h`, `ldap_server.h`: LDAPS and StartTLS on Asio, TLS 1.3 only from the same context as HTTPS. Operations answered strictly in turn on a strand, with reads held back past `ldap.most_pending`; abandon acts when read, unbind in its turn; an idle timeout of its own; the HTTP rate limiter, by address until bound and by caller after; a Notice of Disconnection for anything unreadable. Plaintext carries StartTLS and the rootDSE alone, and bytes following a StartTLS end the connection rather than being acted on under TLS. Writes answer `unwillingToPerform` until L5.
- `ldap.port`, `ldap.starttls_port`, `ldap.base_dn` (required for either), `ldap.most_pending`, `ldap.idle`.
- `lugh/test/fixtures/ldap_client.h`, and the process test over the real binary. `RootBrowser` moved into `node_browser.h`, shared with the OAuth process test.
- Not yet: POSIX numbers (the tree shows them if set, but nothing sets them until `counters` and the allocation exist), which comes with L5.
- Tests: 584 to 612, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-05: LDAP step L4a, the tree and the read operations

- `lugh/ldap/tree.h`: the fixed tree over `Directory`, every entry generated, a filter that pins one entry opening one record and only a general filter reading them all, in a fixed order with page tokens that survive a change. `lugh/ldap/authz.h`: what a bind proves, main password through the authenticator's back-off and an app password cut to its owner's scopes, each refusal the same, and an identity checked again per operation, so a user disabled or an app password revoked stops a connection already bound. `lugh/ldap/operations.h`: search, compare, Who am I?, the rootDSE. No network yet.
- Readings of the plan, for the maintainer to confirm: everyone bound may search from the fixed containers, which say nothing, though the plan's "may not read is not there" could be taken to hide them, because a client bound as itself has to search from somewhere; and a person whose policy is `pwd` binds with their main password even with a TOTP factor enrolled they need not use.
- `Directory::memberships`, so a scan reads the memberships once.
- Tests: 555 to 584, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-04: LDAP step L3, the codec

- `lugh/ldap/`: BER (definite lengths, single-byte tags, stream framing with a size cap), LDAPMessage and every request and response of the plan's table with controls, paged results and Password Modify, DNs (RFC 4514, only the forms the tree has) and filters (three-valued, nesting capped at 16 and 1024 items, with the pinned-value lookup the plan wants). No network yet.
- One reading of the plan: its "a filter on an attribute the entry does not have is Undefined" holds for comparisons, but presence is false, as RFC 4511 says, so `(!(mail=*))` finds those with none.
- Fuzz targets `fuzz_ber`, `fuzz_filter`, `fuzz_dn`, syntax-checked only here: this machine has no clang with libFuzzer. So a test puts a fixed sequence of damaged messages through the same parsers under the sanitizers. It is no campaign: those still need running on a machine with libFuzzer.
- Tests: 527 to 555, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-04: P6 step O5b, the TOTP QR code; P6 complete

- `lugh/signin/qr.h`: a QR encoder from ISO/IEC 18004 (byte mode, level M, versions 1 to 40, all eight masks by the standard's penalties) and an inline SVG with no script or style attribute, so it passes the pages' policy. The enrolment page shows it above the key, which stays as text.
- The test has a reader of its own, written apart from the encoder, which reads every version at the standard's capacity back through its error correction. Checked once outside the suite as well: thirteen symbols, versions 1 to 29, read back exactly by macOS's CoreImage decoder.
- Tests: 521 to 527, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-04: P6 step O10d, opaque access tokens

- An application registered with `opaque_access_tokens` now gets what it asked for: a `lo_` handle in place of the JWT, read at introspection and userinfo, never at `/api/v1`. The signed token stands behind it, so binding, revocation and expiry are the JWT's, and `at_hash` and a DPoP proof's `ath` are over the handle the client holds.
- For the maintainer to confirm: held in memory on the node until P8, not in `grants` as the plan has it, because `verify` never waits.
- Tests: 518 to 521, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-04: P6 step O10c, the whole flow on the real binary

- `node_process_oauth_test.cpp`: root signs in and enrols, registers an application through the API, consents, redeems the code, reads userinfo and refreshes; the sign-out reaches a real HTTPS server over a verified post, and the logout token checks out against the published keys; the old cookie and the refresh token are dead after it. The same across a restart between sign-in and sign-out. Nothing secret reaches the log.
- `docs/oauth.md` written. `docs/api.md` had stale sections (coroutines, signing in as still to come, no sessions routes); brought up to date, with `docs/architecture.md`'s LDAP row and `ACTIVE.md`.
- Found doing it: `opaque_access_tokens` is stored and shown but not honoured.
- Tests: 516 to 518, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-04: The way back to a client after a form

- `form-action 'self'` also covers where a form's answer redirects to, so a browser that enforces that would have stopped a consent answered, or a sign-in resumed, on its way back to the client. Those now leave by a page (`signin::write_leaving`) that goes on by itself and carries a link. An authorisation request that no form led to still gets a 303. Not yet tried in a real browser.
- Tests: 514 to 516, green in the debug, ASan and TSan builds, repeated and shuffled.

## 2026-11-04: P6 step O10b, logout

- `/oauth2/logout` (OIDC RP-Initiated Logout 1.0): an `id_token_hint` of this session's ends it, expired or not; anything less asks the person, on a page whose answer carries the session's CSRF token. A `post_logout_redirect_uri` must be registered exactly by the application the hint or `client_id` names; otherwise it is refused and never followed.
- The session record keeps the applications signed in through it (format 2; format 1 still read), noted before a code or a device approval is issued, so a logout cannot miss one.
- `BackchannelLogout` (OIDC Back-Channel Logout 1.0): when a session ends, however it ends, a logout token (`typ` logout+jwt, two minutes, fresh for each try) goes to each of its applications that registered a URI. Tried again with the wait doubling from 30 seconds, for an hour; delivery and giving up are audited. What waits is in memory, so a restart forgets it.
- `lugh/http/outbound.h`: an HTTPS client that always verifies the certificate and the name, follows no redirect, and has no way to turn that off. `oauth.outbound_ca` changes the roots.
- `signin::write_leaving`: leaving Lugh from a form's answer goes by a page, not a 303, since `form-action 'self'` covers where a form's answer redirects.
- `session_sessions_test` used format 2 as its unknown format; format 2 is now real, so it uses 3. No test removed.
- Tests: 483 to 514, green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O10a, sessions managed and ended

- `Sessions`: a user's sessions listed from memory; one ended by its sid; all of a user's ended but one; and `on_end`, told of every session that ends, however it ends, which O10b's back-channel logout starts from.
- `/api/v1/me/sessions` (list, end one), `/api/v1/me/password` (current and new, through the person's own session only, never a token; every other session of theirs ends), `/api/v1/users/{id}/sessions` (list under directory.read, end all under a new scope, `lugh:sessions.write`).
- A user disabled, removed or with their factors reset loses every session at once, not at the next minute's refresh; a refresh family dies with its session, so the applications' next refresh fails.
- Tests: 479 to 483, green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O9, the device grant

- `lugh/oauth/device_grants.h` (RFC 8628): a device's request answered with a device code and a user code, eight letters from twenty consonants drawn by rejection so each is as likely, shown `XXXX-XXXX` and taken any case with or without the dash. Held in memory on the node for ten minutes; approved or denied once; the approval answered to the device's poll once. Polling sooner than the interval is `slow_down`, and the interval grows by five seconds.
- `/oauth2/device`, and the token endpoint's device_code grant with its errors (authorization_pending, slow_down, access_denied, expired_token), with a refresh token where the application has that grant.
- `/signin/device`: the code typed or carried in from `verification_uri_complete`; a user not signed in goes through the sign-in pages and back with the code; the approval page names the application and what it asks for; approval only for the application's groups and at its least `acr`.
- Tests: 475 to 479 (user codes, polling and slow_down, denial and expiry, and the whole flow from the TV's request to its tokens), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O8b, mTLS

- `TlsContext` gains a client-certificate mode: asked for, never required, never ending a handshake; the chain's check against `tls.client_ca`, when set, kept for the routes. `HttpServer` reads the certificate after the handshake on the mTLS listener and hands its thumbprint (x5t#S256), subject (RFC 2253) and whether it chained to the CA to the routes in `Lugh-Client-Cert-*` headers (`lugh/http/client_certificate.h`), which it removes from every request it reads, on every listener, before it sets its own.
- `tls_client_auth` (RFC 8705 section 2): a client named by its certificate's thumbprint, or by its subject when it chains to the client CA.
- Certificate-bound tokens (RFC 8705 section 3): an application whose `sender_constraint` is mtls gets access tokens with `cnf.x5t#S256`, accepted only on a connection presenting that certificate. The issuer's binding is now a `cnf` object, a DPoP key or a certificate.
- The node runs the mTLS listener when `oauth.mtls_port` is set, with every route but the sign-in pages and the dashboard; the metadata names its endpoints in `mtls_endpoint_aliases` and offers `tls_client_auth` only then.
- Departure, for the maintainer: a second listener rather than the main one asking for certificates (TODO/2026-11-04-oauth.md, O8).
- Tests: 470 to 475 (the listener handing on a certificate, verified against a CA or not; a client's own claim dropped on both listeners; tls_client_auth by thumbprint and by subject; certificate-bound tokens at the API; the metadata's aliases; the settings), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O8b, DPoP

- `lugh/oauth/dpop.h` (RFC 9449): a proof's own parser, since Lugh's JWS parser refuses a key in the header and a proof is exactly that: typ dpop+jwt, alg ES256 or EdDSA, a public jwk, nothing else; checked for its method and URL, made within five minutes either way, used once on the node, and for an access token carrying its hash. RFC 7638 thumbprints, matching RFC 9449's own example.
- The token endpoint binds what it issues to a proof's key: `cnf.jkt` in the access token, `token_type` DPoP, and the key's thumbprint in a new refresh family (the family's record gains it; format 1 is still read). An application whose `sender_constraint` is dpop gets nothing without a proof.
- A bound token is accepted only with the DPoP scheme and a proof by its key, for that request and token, at the API and at userinfo; presented as a bearer token it is nothing.
- Found by the tests and fixed: a bound family's key was checked after the rotation, so a refresh refused for want of a proof left the client's token stale and its next try read as reuse. The key is now checked first, and a refused refresh changes nothing.
- Tests: 464 to 470 (the thumbprint vector, proofs and their refusals, the checker's rules, binding through the token endpoint and the API, a bound family), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O8a, refresh tokens, revocation and introspection

- `lugh/oauth/refresh_tokens.h`: refresh tokens as the maintainer decided, replicated with the session and single use by the family's version. A token is `rt.<family>.<secret>`; the family, in the sealed `grants` table, keeps only the hash of the newest secret. Rotation writes the family at the version it read; a token that is not the newest, or the loser of two rotations racing, is reuse, and revokes the family (RFC 9700 section 4.14.2). A family ends with its Lugh session (`Sessions::live_sid`), at the application's idle and absolute lifetimes, and when revoked. A refresh may narrow the scopes, never widen them, and makes no new ID token.
- The token endpoint takes `refresh_token`, and a code exchange gives one to an application with that grant.
- `/oauth2/revoke` (RFC 7009): the client's own refresh token's family, or its access token, refused by jti until it expires (held in memory on the node; every node holds its own until P8). Always 200.
- `/oauth2/introspect` (RFC 7662): for the client that holds a token, or an api among an access token's audiences; never for a public client.
- Tests: 458 to 464 (rotation and reuse, narrowing, the session's end, the idle lifetime, revocation, introspection), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O7, the authorisation code flow

- `lugh/oauth/request.h`: the authorisation request checked as RFC 6749, RFC 7636 and OIDC Core have it, with Lugh's profile: response_type code only, the redirect URI exactly as registered (any port on a native app's loopback URI, RFC 8252), PKCE S256 required, state required, a nonce with openid, prompt none, login or consent, max_age and acr_values. A request whose client or redirect URI cannot be trusted is refused on a page of Lugh's; every other refusal goes back with state and iss (RFC 9207). The scope cut: what was asked, of what the subject holds, for the token's audiences.
- `lugh/oauth/flow_routes.h`: `/oauth2/authorize`, the resume after sign-in, consent, PAR (RFC 9126), the token endpoint (authorization_code with PKCE, client_credentials) and userinfo. A request without a session good enough for it (none, too weak an acr, prompt=login, past max_age) goes through the sign-in pages, which now carry it and return to it. Only the application's groups' members get a code; a third party asks consent once (`consents`, a new component). Codes, PAR URIs and waiting requests are in memory on their node and used once (`lugh/oauth/expiring.h`).
- `lugh/oauth/client_auth.h`: client_secret_basic, private_key_jwt (a key from the client's JWK Set, iss and sub its client_id, aud this server, a jti never seen, at most ten minutes) and none. tls_client_auth waits for O8's client certificates.
- `lugh/oauth/issuer.h`: access tokens (RFC 9068, at+jwt) and ID tokens (OIDC Core, with at_hash, the claims profile, email and groups allow, and the application's roles); userinfo's claims; and verifying an access token from memory. A bearer token with `lugh` in its audiences is an API caller (`Caller::Kind::service` for a client's own).
- Lugh's encoding gains a strict standard base64 decoder, for HTTP Basic.
- Departures for the maintainer are in TODO/2026-11-04-oauth.md, O7.
- Tests: 443 to 458 (the request's rules with RFC 7636's vector, the whole code flow from no session to userinfo and the API, a code bound to its client, redirect and verifier, refusals at the authorisation endpoint, access groups, consent, client credentials, private_key_jwt, PAR), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O6 (LDAP's L2), app passwords

- `lugh/authn/app_passwords.h`: app passwords in the sealed `app_passwords` table, keyed `<user>/<instance>`. 160 random bits as 32 base32 characters, shown once in lower-case groups of four, typed any case with or without dashes; the first four characters select the record, so a guess costs one Argon2id hash, and a miss costs the same. Each carries a name, a scope set (`lugh:directory.read` unless its creator says otherwise, the maintainer), and optionally the networks it may be used from; it is revoked alone, stops working when its user is disabled, and goes with its user. At most 32 per user. Every change audited.
- The routes: an administrator's for any user under `lugh:credentials.write`, and the caller's own under `/api/v1/me/app-passwords`, never with a scope the caller does not hold.
- Not yet: using one. The LDAP bind (L4) checks it with the sign-in's back-off and cuts its scopes to what its owner's groups grant at that moment.
- Tests: 435 to 443, green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O5, sessions and the sign-in pages

- `lugh/session/`: the Lugh session (`Sessions`), in the sealed `sessions` table keyed by the SHA-256 of a 256-bit handle, held in memory so a request resolves without waiting; 24 hours idle, 30 days at most (the maintainer); a CSRF token per session; ended by signing out, by expiry, and when its user is disabled or removed. `refresh()`, run by the node every minute, reads each session's user and scopes again and saves when it was last seen. The sign-in in progress (`PreSessions`) is in memory on its node, under a visitor cookie that every form's CSRF token is made from with a per-process key; nothing is held for a visitor until a password is accepted, and past 10,000 the oldest is dropped.
- `SessionCallers`: the API's first callers. A session's cookie, and on any request but GET and HEAD its CSRF token in `X-CSRF-Token`.
- `lugh/signin/`: the server-rendered pages, no JavaScript, under `default-src 'none'; style-src 'self'; form-action 'self'`, every value escaped: the password; the second factor, a TOTP or a recovery code; a new password from an enrolment link; enrolling a TOTP factor, a wrong code keeping the same secret and the wrong-code count; the recovery codes shown once; signed in; signing out. Root's first sign-in goes from genesis's password to enrolment. The stylesheet is in the dashboard's tokens.
- `lugh/http/forms.h`: form bodies (Dannan's form decoding; a name given twice refused), cookies (a cookie given twice taken as none), and `__Host-` Set-Cookie values. The server keeps a response's own, tighter CSP. The router gains `add_authenticated()` for `/api/v1/me`, and refuses a protected route without a scope.
- `GET /api/v1/me`: the caller, its scopes, and its session's CSRF token.
- `fuzz_form`, over form bodies and cookies; syntax-checked only here.
- Departures from the plan, for the maintainer: scopes read again within a minute rather than at once, and CSRF required only where something may change (TODO/2026-11-04-oauth.md, O5). Not yet: the TOTP QR code (O5b).
- Tests: 413 to 435 (forms and cookies, sessions and their lifetimes, refresh following the directory, the sign-in in progress, every page's flow and refusal, root's first sign-in, the API through a session, and the real node from genesis's password to an API change through the session), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O4, signing keys, JWKS and metadata

- `lugh/tokens/jose.h`: a public key as a JWK (P-256 and Ed25519, built and read as the SubjectPublicKeyInfo Dannan signs with), and a compact JWS signed and verified with Dannan's ES256 and EdDSA. Parsing refuses every algorithm but those two (no `none`, HMAC or RSA), a missing kid, and any header member but `alg`, `kid` and `typ` (no `crit`, `jku`, `jwk`); verifying takes the algorithm from the key, never from the token. RFC 7515 A.3 and RFC 8037 A.4's signatures verify.
- `lugh/core/encoding.h`: a strict base64url decoder, one spelling per value.
- `SigningKeys`: the sealed `signing_keys` table, held in memory so signing and publishing never wait. A key of each algorithm is made at a cluster's first start; a rotated key is published an hour before it signs, and the key it replaces stays published two hours after that, longer than any token lives; nothing is deleted. An hourly check in the node rotates a key that has signed for 90 days. Every key made or rotated is audited.
- `/oauth2/jwks` (open, cached five minutes), and the server metadata at `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server` when `oauth.issuer` is set (a new setting, `--issuer`, `LUGH_ISSUER`; https, no query, fragment or trailing '/'). The metadata names every endpoint of the profile, which the coming steps serve.
- `/api/v1/keys` and `/api/v1/keys/rotate`, and a new scope, `lugh:keys.write`.
- `fuzz_jws`, over JWS parsing and verification and JWK round trips; syntax-checked only here.
- Tests: 392 to 413 (base64url, JOSE with the RFC vectors and the refusals, the keys' life, the metadata, the key routes, the issuer setting, and the real node serving the same JWKS across a restart), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O3, applications

- `lugh/apps/`: an application's record and every rule that can be checked without the store (`validate()`): client authentication by kind, a JWK Set of public keys only, redirect URIs written exactly (https, no fragment or user information, loopback http for native apps only), grants by kind, prefixes, audiences, role names, the least `acr`, and lifetimes.
- `Apps`: register (a random `client_id`, a secret shown once where `client_secret_basic` is allowed), read, list, replace (keeping what never changes), the groups that may sign in, role mapping, secret rotation with a 24-hour overlap, removal as a tombstone so a `client_id` or prefix is never reused. Scopes and audiences must belong to a registered api; the scope grants check that too now. Every change audited.
- One record per application, holding its access groups and role mapping, so each change is one versioned write; the `app_access` table is unused. Client secrets are in that record as Argon2id hashes; on Dagda (P8) they move to `lugh/secrets` with the other credentials.
- The API: `/api/v1/apps` and its access, roles and secret routes (`docs/api.md`, "Applications"); a new scope, `lugh:apps.write`, which genesis gives administrators with the rest; and the setting `oauth.allow_client_secrets`, off by default.
- The records fuzz target reads applications and scope grants too.
- Tests: 369 to 392 (the record's rules, the component, the routes, and the grant check), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: onto Dannan 0.4.0's settings reader and percent-encoding (rule 3)

- **Dannan pinned to its tag 0.4.0.**
- **Percent-encoding:** the router decodes with Dannan's (`dannan/encoding/percent.h`). Path parameters are decoded strictly (`+` stays `+`, as RFC 3986 has it for paths) and queries as forms (`+` a space); a malformed escape (`%zz`, a trailing `%`) is answered 400 instead of passing through as it did. `Router::percent_decode` is gone; its unit test became a test through a route of both modes and the 400.
- **Settings:** `ConfigLoader` reads through Dannan's reader (`dannan/config/config.h`), which was lifted from it. Lugh declares its settings (`ConfigLoader::settings()`) and keeps its typed `Config` and its own checks: addresses, networks, log levels, the TLS pair needed to serve, the command word, `--passphrase` only for init. The command line keeps only `--help`, `--version` and `--passphrase`; everything else, the command word among it, goes to the reader, and the command is now `Config::command`. Lugh no longer uses yaml-cpp itself (Dannan still does).
- **The environment port** was an exact copy of Dannan's: `lugh::system::Environment` is now `dannan::config::Environment`, `SystemEnvironment` is deleted, and the composition root hands out `dannan::config::process_environment()`, which the IoC check now allows nowhere else.
- `fuzz_cli` is deleted: what it fuzzed, the command line, is parsed by Dannan's reader now, and Dannan fuzzes its own parsers.
- **Tests: 378 to 369.** A drop, so here is why. The CLI tests went from 11 to 3: what they covered (both flag forms, every setting's flag, unknown and valueless flags) is Dannan's reader's, tested in Dannan; the command word, stray words and `--passphrase` moved into the config tests. The config tests went from 19 to 18: the three layer-order tests became one (`TheLayersInOrder`), `TheStateDirectory` and `TheBreachedPasswordList` were folded into the defaults and file tests, and three were added (the command word, `--passphrase` only for init, unknown and valueless flags); the bad-values test also checks a bad log format now. Green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O2, the scope model

- `lugh/scopes/`: what a scope is (RFC 6749 section 3.3's word, at most 1024 bytes) and its four kinds, Lugh's own, OIDC's, an application's `<prefix>:<name>` and Lir's topic scopes; the space-delimited list split and joined. Lugh's own scope names move here from `lugh/api/scopes.h`, which now refers to them.
- Lir's topic-scope grammar as the maintainer decided it (`lir:pub|sub|retain:<filter>`, `{sub}` the one substitution, a whole level), decoded strictly and encoded with Dannan's percent-encoding (Dannan pinned to 32f163b for it). A grant whose filter is not a valid MQTT filter is refused, and an encoded scope decodes to what was encoded.
- `scope_grants` (a new table): which scopes each group grants, versioned for ETags; a user's effective scopes are the union over their groups, read when needed. Genesis grants `administrators` every Lugh scope.
- The API: `GET /api/v1/scopes`, and `GET`/`PUT /api/v1/groups/{id}/scopes` (`lugh:policies.write` to change, with `If-Match`).
- `fuzz_scope`, a libFuzzer target over the list, the kinds and the topic grammar's round trip. Syntax-checked only: this machine has no clang with libFuzzer.
- Not in O2, and why: an application's prefix is checked against the registered apps in O3; `ScopeSource` over an in-memory image of the grants is P8's, since nothing installs it before Lugh runs on Dannan's Context.
- Tests: 356 to 378 (the scope rules, the topic grammar, the grants, the routes, genesis's grant), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-04: P6 step O1, the name parts and the POSIX number

- `User` gains `given_name` and `family_name` (optional, printable, at most 128 bytes) for OIDC's `profile` claims and LDAP's `givenName` and `sn`, and `posix_number`; `Group` gains `posix_number`. Nothing allocates a number yet; LDAP's L-steps do (`TODO/2026-11-04-ldap.md`).
- The user and group records move to format 2. Format 1, which the frozen store holds, is still read, as having no name parts and no number, and never written.
- The API takes and shows `given_name` and `family_name` on create and `PATCH`, and shows `posix_number` once there is one (`docs/api.md`).
- Tests: 353 to 356 (the new record format, format 1 still read, the POSIX flag checked; the directory's name parts; the API's), green in the debug, ASan and TSan builds, and `ctest`.

## 2026-11-03: Aligning with Dannan and Dagda (feature/dannan-alignment, in progress)

The maintainer, 2026-11-03: Lugh uses Dannan as its network and Dagda as its datastore, no code is
duplicated between the three, and all three share one style, set of conventions and
layout. Kept until Dagda carries Lugh's spaces: the sealed store and keyring ("Keep the
store until Dagda"). The stack and its seams are in `../dagda/TODO/2026-11-03-stack.md`.

- The GPLv3 header block ("Lugh - The Directory") and `LICENSE`; Dannan linked, pinned to a
  commit of `feature/wire-v1` until a tag carries its Context; MacPorts for every dependency.
- Dannan's layout: `lugh/<subsystem>/`, `lugh/test/` flat, `lugh/fuzz/`, `tools/` (the service
  is `lugh-node`), `test/process/`, `TODO/COMPLETED.md`.
- From Dannan in place of Lugh's own: SHA-256, the constant-time compare and hex
  (`dannan/identity/crypto.h`), Argon2id and its ceiling on stored costs
  (`dannan/identity/argon2.h`, `Argon2Costs::valid()`), and signing
  (`dannan/identity/signing.h`; Lugh's copy deleted, it had no user yet).
- Finding: the unit count went from 389 to 373. The tests that went were of what Lugh no
  longer owns: its SHA-256, compare and signing copies, and the RFC 9106 Argon2id vectors,
  all tested in Dannan against the same published vectors.
- The wall clock and the steady time source are Dannan's (`dannan/contract/`), and the tests
  step Dannan's `SteppedTime` and `SteppedWall`.
- Secure memory, the record codec, HKDF and AES-256-GCM are Dannan's: `SecureBuffer` on
  Dannan's locked pages, every record and file format written with Dannan's `Writer` and
  read with its `Reader` (`lugh/core/codec.h` holds only `SecureWriter` and
  `decode_whole`), the keyring's KEK from `hkdf_sha256_secret`, and `crypto/aead` reduced to
  the sealed-value framing (nonce, ciphertext, tag) over `aes_gcm_seal` and
  `aes_gcm_open_secure`. The keyring and table log formats keep their bytes. The node
  hardens itself with `harden_process()`. Lugh's `core/byte_io.h`, `core/secure_memory`
  and `crypto/hkdf` are deleted.
- Finding: the unit count went from 373 to 353, all of it what Lugh no longer owns: its
  byte codec, secure memory and HKDF tests, the GCM known-answer vectors and the Argon2
  ceiling (each tested in Dannan), and the test that a broken random source seals nothing,
  since Dannan draws the nonce itself and Lugh cannot inject that failure any more.
- The warning that key material could not be locked into memory reads Dannan's
  process-wide count, `unlocked_secure_allocations()`, added at Lugh's request (Dannan
  6d173c1, which Lugh is now pinned to); the node also warns when `harden_process()` falls
  short.
- `Secret` is Dannan's: move-only, on locked pages, compared in constant time with `==`.
  `lugh/core/secret.h` keeps only the redaction text and the text on either side of a
  secret (`text_secret`, which wipes the string it is given, and `secret_text`). A secret
  read a character at a time is built in a `SecureBuffer` and handed over. Where a caller
  still needs a secret it passes on, the copy is written out at the call site.
- Finding: the unit count went from 353 to 351: the copy and growth tests of Lugh's
  `Secret`, which no longer exist to test.
- Randomness is Dannan's: `random_bytes` for what is not secret (ids, salts) and
  `Secret::random` for what is, through `secure_random()` in `lugh/core/secure_bytes.h`
  when it must land in a `SecureBuffer`. The `Random` port, `SystemRandom` and the test
  doubles `FixedRandom` and `CountingRandom` are deleted, as is the `random` argument of
  every constructor and of `hash_password`, `make_file_header` and `Keyring::rotate`. A
  failed generator throws: a route that meets one answers 500, and a start or `init` that
  meets one stops.
- Finding: the unit count went from 351 to 347. The four tests that went made the random
  source fail and saw a user, a factor, root's password or a keyring refused; with Dannan
  drawing the bytes, a test cannot make it fail. The tests that relied on two rigs drawing
  different bytes now draw from the real generator.
- Logging is Dannan's (`dannan/status/log.h`): the node has one `LogSink`, made in
  `tools/lugh_node.cpp` by `console_sink(format, level)` (text, or JSON lines through
  Dannan's `JsonSink`, added at Lugh's request), and each component takes the sink and
  scopes its own `ScopedLogger` ("store", "audit", "authn" and so on), as a Dannan component
  takes `Context::logger(scope)`. `log.level` and `log.format` are read with Dannan's
  `parse_log_level` and `parse_log_format`, so `all` is now a level. The tests record
  through `RecordingSink`. Lugh's `loggers/` (from blackraven-admin) is deleted, and the IoC
  check refuses a concrete sink outside the composition root. Dannan is pinned to ca8a565.
- Finding: the unit count went from 347 to 338: the tests of `LoggerScoped` and
  `LoggerStdIO`, whose behaviour is now Dannan's and tested there.
- Every lock is Dannan's (`dannan/contract/thread_safety.h`): `Mutex` under `Lock`, the
  state it guards `DANNAN_GUARDED_BY` it and a helper called with it held
  `DANNAN_REQUIRES` it, in the library and the test fixtures alike, so clang's analysis
  (`-Werror=thread-safety`) checks every access. A table's state lock in the sealed store
  is an `IoMutex`, since a record that does not open is logged with it held. Opening a
  table and loading its keys now take that lock around the state they touch, though
  nothing else can see the table yet, so the analysis can prove every access. The IoC
  check refuses a standard lock outside the composition root.
- The tests write only inside the build tree, as Dannan's do: `TempDirectory` is Dannan's
  `TempDir` (under `build/test-tmp`) with a `write()` helper, and ctest gives the process
  tests `TMPDIR` there. Before, both used the system temp directory.
- HMAC-SHA-256 is Dannan's, and Lugh had no caller of its own copy; HMAC-SHA-1, which only
  TOTP uses, moved into `authn/totp.cpp`. `crypto/hmac` is deleted. Finding: the unit count
  went from 338 to 335, the HMAC known-answer tests; HMAC-SHA-1 is still checked through
  RFC 4226's and RFC 6238's vectors.
- `CONTRIBUTING.md` from Dannan's, section for section, with Lugh's own rules on secrets
  and inversion of control beside them, and a local `CLAUDE.md` (gitignored, as Dannan's
  is) from Dannan's. `docs/code-style.md` is gone: its rules are in `CONTRIBUTING.md`, and
  its tables of what was lifted from where are `docs/provenance.md`. Following the rule
  The maintainer set for all the source repositories, sanitizers now run before a release rather
  than routinely, which `code-style.md` had made a deliberate Lugh exception.
- Dannan's warning set on every target: `-Wshadow -Wconversion -Wno-sign-conversion` beside
  `-Wall -Wextra -Wpedantic`, under `-Werror`. The library and the node were already
  clean; three tests were not (a shadowed name twice, a narrowing in a loop).
- `SystemFiles::write` is Dannan's `durable_replace_file`, or `durable_create_file` when an
  existing file must not be replaced (added at Lugh's request; it ends in `link()`, so of
  two inits racing exactly one makes the keyring, and Dannan's own key custody had the
  same race, now closed). Lugh's temporary, sync, rename and link code is deleted. Dannan
  is pinned to bd2f720. Finding: a write now makes the directories its file needs, where
  Lugh's refused; the test says so. At Lugh's request Dannan makes them 0700, one level at
  a time, as Lugh's own did (Dannan 7f02e58, Lugh's pin), and the test checks it.
- The rules follow the maintainer's decisions of 2026-11-04: Lugh keeps its presets (the `fuzz`
  preset's option is fixed: `LUGH_BUILD_FUZZING`, not the old `LUGH_FUZZ`) and runs the
  sanitizers routinely, its two exceptions to the stack. The stale `build-asan` and
  `build-tsan` trees from the old layout were deleted and built afresh. Under ASan and UBSan
  and under TSan, `lugh_tests` (335) and `ctest` (5) pass. Finding: ASan stopped the test
  binary as GoogleTest registered its tests, with a false container overflow where
  MacPorts' uninstrumented GoogleTest meets libc++'s annotated containers; the ASan test
  binary now turns container-overflow detection off (`lugh/test/sanitizer_options.cpp`),
  every other check on.
- Dannan is pinned to its first release tag, 0.2.0 (`LUGH_DANNAN_TAG`), in place of a
  commit, and linked as `dannan::dannan`, the name an installed Dannan exports. Under the
  debug build, ASan with UBSan, and TSan, `lugh_tests` (335) and `ctest` (5) pass.
- No Python (the maintainer, 2026-11-04), first part: the IoC check is a GoogleTest test,
  `lugh/test/node_ioc_check_test.cpp`, in `lugh_tests`, and `tools/lugh_ioc_check.py` and
  its ctest entry are gone. The same patterns and adapters; the one lookbehind is written
  without one, as `std::regex` has none. Each pattern now proves it catches an example of
  what it forbids, and that some of Lugh's own calls (`_time.now()`, `boost::asio::write`,
  Dannan's `Lock`) are not caught; a `getenv` planted in a library file was named and failed
  it. A plain-text prefilter keeps the scan near 0.2 s in a debug build. Unit count 335 to
  339; `ctest` 5 to 4.
- No Python, second part: the shutdown, `init` and API process tests are GoogleTest tests in
  `lugh_tests` (`node_process_shutdown_test.cpp`, `node_process_init_test.cpp`,
  `node_process_api_test.cpp`), check for check what the Python ones did, over a fixture
  (`lugh/test/fixtures/node_process.h`) on Dannan's `ChildProcess`. Dannan gave
  `ChildProcess` an environment, standard input, a pseudo-terminal, raw reads and any signal
  for them (ca029bb, Lugh's pin until the next tag; the pin is now `LUGH_DANNAN_REF`, a tag
  or a commit). The certificate is made in-process rather than by the `openssl` command,
  and every request and wait has a deadline. `test/process/` and the ctest entries are gone;
  `ctest` runs `lugh_tests` alone. Seven tests where there were three scripts: 339 to 346,
  passing in the debug, ASan and TSan builds.
- Callback style, first piece: `lugh/core/completion.h`, the one place that keeps Dannan's
  promise for an operation's answer (posted to the caller's executor exactly once, the
  answer or the deadline's, never inline), with five tests, run twenty times under TSan
  with no report. `Executor` moved there from `core/task.h`. The design for the rest is in
  `TODO/ACTIVE.md`. 346 to 351.
- Callback style, the audit log: `open`, `record`, `entries` and `verify` take Dannan's
  shape. The async lock held across numbering and writing is now a queue on the log, one
  write in flight, each entry numbered only once the one before has settled, so the chain
  keeps no gaps and no forks; a caller past its deadline is told the entry may yet be
  recorded, and it keeps its turn. `entries` answers `failed` on a store failure or the
  deadline rather than a short page. The frozen store is reached through
  `lugh/store/store_calls.h`; the layers not yet converted reach the log through the
  temporary bridge `lugh/core/awaited.h`; the tests through `wait_for` and
  `lugh/test/fixtures/audit_calls.h`. A new test has 100 callers on four threads record at
  once: one intact chain of 100, no TSan report in five runs. 351 to 352.
- Callback style, the directory: all twenty operations take Dannan's shape, each one
  `Completion` over steps that each start the next (names checked free, the record put,
  the change audited, memberships tidied in turn). A read answers `Outcome`, `failed` and
  never "absent" when the store fails or the deadline passes; a coroutine caller in
  transition gets the value through `awaited_value`, which throws for a read that could
  not happen (the router answers 500), and the dependents' `forget` (still coroutines) is
  run through `spawned`. The 77 calls from the routes, authn, the node and the tests were
  rewritten by rule, not by hand: the operation's answer type from a table, a deadline
  added, and `std::nullopt` where `expected` had been left to its default. A new test reads
  and writes through a store slower than the deadline: the read is `failed`, the write says
  it may yet be made. 352 to 353, in the debug, ASan and TSan builds.
- Callback style, the policies and the passwords. The step helpers (`answering`, `refusing`,
  `in_turn`, and `on_pool` for blocking work) are `lugh/core/steps.h`. Argon2id runs on the
  hashing pool through `on_pool`, the password held in a `shared_ptr` where a step needs it,
  since a `Secret` is not copied; `verify` and `has_password` answer `failed` rather than
  a false "no" when the store fails or the deadline passes. The directory's `Dependent`
  takes the callback shape; factors, not yet converted, answers it by running its
  coroutine through `spawned`. 353, in the debug, ASan and TSan builds.
- Callback style, the enrolment links: all seven operations. A token is a `Secret`, held in
  a `shared_ptr` between steps and moved out at the end. "No such link" stays an ordinary
  refusal (the callers act on it), so `peek`, `link` and `spend` keep their `Outcome` through
  the bridge; only a store failure or a passed deadline is `failed`. 353, in the debug, ASan
  and TSan builds.
- Callback style, the factors: all nine operations, TOTP and recovery codes, with the codes'
  Argon2id on the hashing pool. The temporary wrapper that let `forget` run as a coroutine
  is gone. A wrong code, a replay and a lost race stay `refused`; a failed store or a passed
  deadline is `failed`, never a wrong code. 353, in the debug, ASan and TSan builds.
- Callback style, genesis: one chain of steps (no one there yet, root, administrators, the
  membership, the password, the first sign-in, the audit entry), each holding copies of
  what it needs, so the `Genesis` built for the call may go at once. 353.
- Callback style, the authenticator: every sign-in step, enrolment, removing a factor and
  the reset. The rules are as they were (back-off before any hashing; the same work for a
  known and an unknown name; the link spent only after the password is accepted; every
  refusal audited), the steps now one chain each. One change of behaviour: a read that
  could not happen part way through a sign-in used to throw out of the coroutine; it is now
  answered `Step::Kind::failed`, the kind that was always meant for it. Every authn
  component and the directory and audit log are now callback style; the routes, router
  and node still reach them through the bridge. 353, in the debug, ASan and TSan builds.
- Callback style, the router and every route. A handler is a plain function, run on the
  router's executor with that executor in its context; a request is in flight until it is
  answered, once, and one that throws while starting is answered 500 as before. The routes
  call the directory, authn and the audit log directly, one chain each, with a deadline
  each (`kRouteDeadline`), and answer a failed read as a 500 rather than by throwing. The
  500 now says "the request could not be completed", not "nothing was changed": past a
  deadline a change may yet land. The API fuzz target's handler follows (syntax-checked
  with the library's flags; no libFuzzer here to build it). 353, in the debug, ASan and TSan
  builds.
- The callback change is done above the frozen layers. The node's start-up stays a
  coroutine sequence: it runs the frozen keyring, store and files in turn, and converting it
  now would only trade one bridge for another; it and the bridge go with them.

## 2026-10-18: P5, the management API (not committed)

- **`/api/v1`** (`src/api/`, [docs/api.md](../docs/api.md)): users (list, find by name or address, create, read, change, disable, remove), their groups and factors, removing a factor, resetting them all, enrolment links; groups and their members; the global and per-group assurance levels; the audit log a page at a time, and a walk of its whole chain.
- **Scoped permissions**: `lugh:directory.read`, `lugh:directory.write`, `lugh:credentials.write`, `lugh:policies.write`, `lugh:audit.read`. Every route declares its scope in the router, after blackraven-admin's role-checked routes: `401` with `WWW-Authenticate` for no credential, `403` for a missing scope, and callers limited per caller once known and per address until then.
- **ETags**: a user or group carries its version as a strong ETag; `PATCH` and `DELETE` need `If-Match` (`428` without, `412` stale, `*` to skip). Policies and memberships are idempotent `PUT`s and `DELETE`s, with no version.
- **Errors**: one shape, a `Fault` mapped to one status each, and unknown or mistyped body fields refused, never ignored.
- **Genesis** (`authn/genesis`), replacing a bootstrap credential at the maintainer's word: there are no static credentials, tokens, keys or settings. `lugh init` on a cluster's first node makes `root`, in `administrators`, with a random 144-bit password shown once on standard error and kept only as its hash; it is the one credential a cluster is born with. Root's first sign-in goes from that password to enrolment, once (`EnrolmentLinks::first_sign_in_*`); then root signs in as anyone does. Genesis refuses a directory with anyone in it. A person no longer needs an email address (root has none).
- **Async all the way down** (the maintainer: "it should all be async"; a first pass that put blocking work on a pool behind the routes was not enough). Every operation that waits is a C++20 coroutine on Boost.Asio (`Task<T>`, `core/task.h`): the `Store` interface and `SealedStore`, the `Files` and `Console` ports, the keyring manager, the audit log, the directory, passwords, factors, policies, enrolment links, genesis, the authenticator and every route handler. `SystemFiles` and `SystemConsole` run their system calls on a `blocking` pool, and Argon2id runs on a `hashing` pool of two threads, both through `offload()`; the caller is suspended and holds no thread. The store holds each table's writes in order with an `AsyncMutex` (`core/async_mutex.h`) across the synced append, and its state with a `std::mutex` only for moments; readers never wait on the disk, and a write is invisible until it is durable. The router spawns each handler as a coroutine, with at most 256 in flight (`503 busy` past that), and answers a handler that throws `500`, once. Startup and `lugh init` are coroutines on the io_context. The `WorkPool` lifted earlier in P5 is gone. Sign-in steps take the `SignIn` by value and hand back the next, recovery codes travel as `Secret`, and a value written to the store is `SecureBytes`. Asio's `awaitable` is `[[nodiscard]]`, so a forgotten `co_await` is a compile error; it caught two in the tests.
- **Until P6 nothing opens the API**: no caller resolves, and every route answers 401. The routes are tested through a fixed-caller fake (`tests/fakes/fixed_callers.h`).
- **Tests**: 389 unit tests, among them a store whose append is held open (and which fails if the table's write lock is taken away), showing a read of that table and a write to another finish meanwhile, the held write invisible until it lands, and a second writer queued behind it without a thread; concurrent writers through a router on a real thread pool (64 creations at once; 32 racing for one name, one winning; 16 racing adds making one membership); the router spawning handlers rather than answering inline, refusing at its in-flight limit, and answering a throwing handler once; `offload` and `AsyncMutex` themselves; every route over the API rig, the router's scope, 401, 403 and per-caller limits, and genesis with root's first sign-in; the `init` ctest now checks genesis shows root's password once, on standard error only and nowhere on disk; a new `api` ctest runs the real binary after genesis and finds the API closed to every credential presented, root's password included. A new fuzz target over the route table, query, percent-encoding, `If-Match` and body checks (`fuzz/api_request_fuzz.cpp`), run here under ASan with a stand-in driver: 300,005 inputs, no crash. All green under `debug`, `release`, `asan` and `tsan`.

## 2026-10-18: P4, directory and authentication (not committed)

- **Directory** (`src/directory/`): users (person or service; enrolled; disabled), groups and memberships over the store, with names and addresses checked and folded to lower case and unique through the store's indexes, display names checked as printable UTF-8, and every write made against the version read, so the API's ETags have something to check. Removing a user removes their memberships and, through `Dependent`, their password and factors; the name is then free for someone new under a new ID.
- **Audit** (`src/audit/`): the `audit` table, one hash-chained record per entry, with `verify()` naming the first entry missing, altered or out of order. Every change the directory and authn make is recorded, with who made it and from where.
- **Passwords** (`authn/passwords`): Argon2id hashes in `credentials`, with their costs stored so a hash under old costs is made again at the next sign-in. At least 12 characters, at most 256 bytes, not the user's own name or address, and not on the local breached list (`authn.breached_passwords`, held as SHA-256 hashes, case folded). An unknown user costs the same hash as a known one.
- **Second factors** (`authn/factors`, `authn/totp`): TOTP (RFC 6238: SHA-1, six digits, 30 seconds, one step either way), confirmed by a code before it counts, with the last step stored so a code works once, even with two sign-ins racing; ten recovery codes of 80 bits, Argon2id-hashed, with a four-character selector so a guess costs one hash.
- **Policy** (`authn/policy`): `pwd`, `mfa`, `phr`, global and per group, the strictest winning, `mfa` by default (open question 9).
- **Enrolment** (`authn/enrolment_links`): one-time links in `grants`, stored as the SHA-256 of the token, 72 hours, spent by a conditional removal so they work once, and a new link ending the old.
- **Sign-in** (`authn/authenticator`): the password, then a TOTP or recovery code; or a link, a new password, and a TOTP factor enrolled, which ends with the recovery codes. Enrolment starts only from a link, never from a password alone. Refusals all look the same. Five wrong codes end a sign-in, a sign-in lasts 15 minutes, and failures back off per account and per address (`authn/backoff.h`), answered before any hashing. The last factor cannot be removed while policy needs one, and an administrator's reset means enrolling again from a new link.
- **Also**: `crypto/hmac` (HMAC-SHA-1 for TOTP, HMAC-SHA-256), `core/encoding.h` (hex, base32, base64url), `core/outcome.h` (results with a fault the API will map to a status), `field()` in `ByteWriter`/`ByteReader`. `main` opens the audit log and builds the directory and authn after the store; nothing reaches them over HTTP until P5 and P6.
- **Deferred**: `WorkPool` moves to P6, with the first route that hashes a password. Session revocation, re-authentication before a factor change, and telling the user about one need sessions (P6).
- **Tests**: 345 unit tests, among them the RFC vectors for HMAC (2202, 4231), HOTP and TOTP (4226, 6238) and base32/base64url (4648), and the whole sign-in run through over a MemoryStore with a ManualClock. Mutating the replay check, enrolment from a password, link expiry, the last-factor rule, the breached list or the audit chain each fails tests. A new fuzz target over every record parser and the text a person types (`fuzz/records_fuzz.cpp`), run here under ASan with a stand-in driver: 400,010 inputs, no crash. All green under `debug`, `release`, `asan` and `tsan`.

## 2026-10-18: P3, the store on one node (not committed)

- **Store** (`src/store/`): `Store`, the interface (get, find by a unique index, list, put and remove with an optional expected version, final removals with kept tombstones, per-record versions), `SealedStore` on disk, and `MemoryStore` in `tests/fakes/`. One log per table under `<state>/store/`, after Macha's sealed journal: a file header sealed under the table's data key, so a wrong keyring is refused before any frame is judged; one AES-256-GCM frame per change, bound to the table, the epoch and the previous frame's tag, so frames cannot move between tables or files, be reordered, dropped from the middle or replayed; every write synced before it is acknowledged, and cut back off the file if it fails part way.
- **Recovery**: a torn tail (nothing that looks like a frame after the break) is cut at open and logged; damage with frames after it stops the open, naming the file and the byte, after Macha's pack recovery but failing closed. A table whose failed write could not be cut back refuses writes until restart.
- **Compaction and keys**: a table more than half superseded past 1 MiB is rewritten whole under its current data key and renamed over the old, after Macha's pack compaction. `rotate()` makes a new data key epoch, saves the keyring before anything is sealed under it, and compacts. The first open of a table makes its data key.
- **Indexes**: declared per table, derived from the record value, unique, rebuilt at every open.
- **Not lifted from Macha**, and why: the rest of `LocalStore` and the ledger, which serve content-addressed objects placed by a DHT (`code-style.md`, "From Macha").
- **Ports**: `Files` gained `append`, `truncate` and `remove`. `crypto::sha256`, and 16- and 64-bit fields in `ByteReader`/`ByteWriter`.
- **Service**: `main` opens the store's 14 tables after the keyring and before it listens.
- **Tests**: 247 unit tests, among them a contract suite run against `SealedStore` and `MemoryStore` alike, every truncation of a log, damage, reordering, replay, a log moved to another table, another keyring, a failed write, a failed cut-back, compaction (and a failed one), rotation (and one whose keyring cannot be saved), and a torn tail on a real disk. The table log has a fuzz target (`fuzz/store_log_fuzz.cpp`), run here under ASan with a stand-in driver. All green under `debug`, `release`, `asan` and `tsan`.

## 2026-10-18: P2, crypto and keys (not committed)

- **Crypto** (`src/crypto/`, one thin layer over OpenSSL 3): AES-256-GCM seal and open with associated data and a random nonce from the `Random` port; HKDF-SHA256; Argon2id (OpenSSL 3.2+) with RFC 9106's second recommendation as the default and bounds on stored costs; ES256 and Ed25519 signing keys with PKCS#8 export and import, raw public keys (the uncompressed P-256 point, for a JWK) with an on-curve check, and JOSE-form signatures; constant-time comparison. Each is tested against its published vectors: the GCM specification's AES-256 cases, RFC 5869, RFC 9106, RFC 8032 and RFC 6979.
- **Memory**: `SecureBytes` and `Secret` hold their bytes in `core/secure_memory`, pages of their own that are locked into memory, kept out of core dumps on Linux and wiped when freed. Not OpenSSL's secure heap, because OpenSSL's Argon2id then takes its whole 64 MiB from that heap and fails; found by the init test. `Random` gained `fill`, so a key is made where it lives.
- **Keys** (`src/keys/`): the keyring file (`<state>/keyring`): a header saying where the master key comes from, then the data keys sealed whole under a KEK derived from the master key by HKDF, salted with the keyring's random id, with the header as associated data. Data keys per name and epoch, rotation, adding a key made elsewhere (for P8's join), and re-keying under a new master key. Written atomically (temporary, fsync, rename or link, directory fsync) and never replaced by init. The format's two parsers have a fuzz target (`fuzz/keyring_fuzz.cpp`), which also checks every parse writes back to the same bytes.
- **Master key**: from the systemd credential `lugh-master-key` in `$CREDENTIALS_DIRECTORY`, or from a passphrase of 16 characters or more typed at start and stretched by Argon2id. `lugh init` writes a new key to standard output for `systemd-creds encrypt`, refusing a terminal, and saves the keyring only once the key has gone; `lugh init --passphrase` asks twice. The service opens the keyring before it listens, and will not start without it.
- **Ports**: `system::Files` (`SystemFiles`, `MemoryFiles`) and `system::Console` (`SystemConsole`, `ScriptedConsole`). The IoC check now also refuses POSIX file calls, terminal calls and the process's memory outside the adapters.
- **Config and CLI**: `state.directory` (`LUGH_STATE_DIRECTORY`, `--state-directory`), the `init` command and `--passphrase`. `init` needs no TLS pair.
- **Deploy**: the unit passes `--state-directory /var/lib/lugh`, loads `LoadCredentialEncrypted=lugh-master-key:/etc/credstore.encrypted/lugh-master-key`, and sets `LimitMEMLOCK=16M`. `host-setup.sh` makes `/var/lib/lugh` (0700, lugh) and `/etc/credstore.encrypted` (0700), and warns while the credential is missing. `scripts/dev-init.sh` makes a development keyring and credential under `config/dev/`.
- **Tests**: 185 unit tests; a new `init` ctest that runs the real binary through init and start with a credential, with a passphrase, with each wrong, and with a terminal on standard output; the shutdown test now runs init first. All green under `debug`, `release`, `asan` and `tsan`.
- **Docs**: `architecture.md` (encryption at rest as built), `code-style.md` (key material, OpenSSL's secure heap, the new ports, the IoC rules, the test vectors), `README.md` (running with a keyring, and `lugh init` on a node).

## 2026-10-18: P1, skeleton (committed as `700092b`)

- **Build**: CMake 3.23+ with the presets `debug`, `release`, `asan`, `tsan` and `fuzz`; `lugh_core` (static), `lugh` and `lugh_tests`; `-Wall -Wextra -Wpedantic -Werror` and Clang's thread-safety errors on by default; hardening on by default (`_FORTIFY_SOURCE=3` outside Debug and sanitizers, `_GLIBCXX_ASSERTIONS`, libc++ fast hardening, `-fstack-protector-strong`, `-fstack-clash-protection` where it exists, CET or PAC/BTI by architecture, PIE, and `relro`/`now`/`noexecstack` on Linux), each flag probed under `-Werror` first because Apple's clang accepts some and then warns they did nothing. Boost 1.87+, OpenSSL 3, yaml-cpp, GoogleTest, Python 3.
- **Service**: Beast over TLS 1.3 and nothing older, with no plaintext listener and the TLS pair required by the config loader; a handshake timeout; the security headers (HSTS, nosniff, CSP, Referrer-Policy) set on every response after the middleware; `Server: Lugh` and no version anywhere a stranger can read it. The router with open routes, path parameters, 404/405 and per-address rate limits; `/health` and `/ready` saying ok and nothing else. `ClientAddress` trusts no proxy unless `proxy.trusted_networks` names it. Layered config (file, `secrets.yaml`, `LUGH_*`, CLI) with unknown keys warned and bad values refused naming their source. `Secret` (`core/secret.h`): a type that converts to nothing, so a secret cannot reach a log line, with wiping and constant-time comparison. Ports `Clock`, `Random`, `Environment` with system adapters. Core dumps refused by `main`.
- **Tests**: 89 unit tests; the shutdown test (makes its own certificate, speaks TLS, SIGTERM and SIGINT exit 0 within 5 s); the IoC check. All green under `debug`, `asan` and `tsan`. HTTP tests run the real server on port 0 over TLS with an in-process self-signed certificate (`tests/helpers/test_certificate.h`), and prove TLS 1.3 is negotiated, TLS 1.2 and plaintext are refused, and the headers are present. End to end: `scripts/dev-cert.sh` then `./build/lugh --config config/config.yaml`; `curl -sk` sees `{"status":"ok"}`, `--tls-max 1.2` fails the handshake, `http://` gets nothing.
- **Fuzz**: `fuzz/cli_fuzz.cpp` and the `fuzz` preset with a short ctest run per target. Not built here (Apple's clang has no libFuzzer).
- **Deploy**: `deploy/lugh.service` (user `lugh`, `CAP_NET_BIND_SERVICE` only, `StateDirectory=lugh`, `LimitCORE=0`, blackraven-admin's sandbox) and `deploy/host-setup.sh` (user, config and TLS directory permissions). `cmake --install` installs binary, config, docs and unit, runs host setup and restarts.
- **Docs**: `docs/code-style.md` (the rules, the Secrets section, IoC, errors, logging, tests, build, and the lifted-from tables: blackraven-admin for nearly all of it, AthenaSIP's `tls_context` for TLS), `README.md`, `.gitignore` (build trees, `config/dev/`, `*.pem`, `*.cred`, `secrets.yaml`, `CLAUDE.local.md`).

## 2026-10-18: P0, initial architecture (not committed)

- **Docs**: `docs/architecture.md` sets out the design as understood: the OAuth 2/OIDC, management API, LDAP and C++ library surfaces; the store built on Macha's sealed journal, packs and replication; the T.O.M.S styling for the dashboard; blackraven-admin's conventions; the security model; and the open questions.
- **TODO**: `ACTIVE.md` and `COMPLETE.md` created, with the phase plan P1 to P12.
