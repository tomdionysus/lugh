# Changelog

What each release added, changed and fixed, and what a project of the stack can now take from Lugh in place of its own
code. Newest first. The tags are on `main`.

## Unreleased

### Changed (breaking, for `lugh_client`)

- The callback vocabulary is the stack's, Dannan's `contract/completion.h`: `lugh::Fault`, `Outcome`, `Nothing`,
  `Completion`, `Done`, `Executor`, `Deadline` and `answer_now` are Dannan's own types now, not copies, so a dependant
  passes one where the other is asked. Code that names `lugh::` keeps compiling. A `switch` over `Fault` must handle
  two new kinds:
  - `unavailable`: a server or a part of the directory could not be reached. `lugh_client` answers it where it said
    `failed` for a connection that failed, an issuer whose discovery could not be fetched, and an API or revocation
    endpoint that answered 503.
  - `timed_out`: no answer within the deadline; a write may yet land. Lugh's own deadlines answer it where they said
    `failed`.
- `lugh::undecided(fault)` says whether a request was left undecided (failed, unavailable or timed out), never refused.
- The API answers `503 unavailable` and `503 timed_out` for the two (`docs/api.md`); `500 failed` keeps the store, the
  keys and the randomness.

### Changed

- Lugh's encodings (hex, base32, base64, base64url, the UTF-8 checks) are Dannan's `encoding/base.h`, which was taken
  from Lugh's; the spellings each accepts are unchanged. A refresh token's secret part decodes straight into secure
  memory.
- TOTP computes with Dannan's `identity::hmac_sha1`; Lugh's own HMAC-SHA-1 is gone. The codes are the same (RFC 4226
  and RFC 6238's vectors).
- A user's or group's id is Dannan's `identity::RandomId`, spelled as before: thirty-two lower-case hex digits. Client
  ids, key ids and token ids keep their own spellings, which relying parties see.
- Address ranges (`proxy.trusted_networks`, an app password's networks) are Dannan's `listen::Prefix`; Lugh's `Cidr` is
  gone. What is accepted is unchanged: host bits set past the length were refused before and still are
  (`10.0.0.1/8` stops the start, naming the setting). New: an IPv4-mapped range (`::ffff:10.0.0.0/104`) is read as
  the IPv4 one it means.
- `lugh-node` logs through Dannan's `status::SwappableSink`: stderr until the configuration is read, then the
  configured sink, under one logger. The tests capture with Dannan's `test::RecordingSink`; Lugh's copy is gone.

## 0.4.0: the stack's config names (2026-11-22)

A release for source dependants, as 0.3.0 was: its Debian package follows Dagda's release on Dannan 0.10.x in the apt
repository.

Repin, with this release's gate: Dannan 0.10.0 to 0.10.2, two patches with 0.10.0's ABI. From their release notes
nothing in Lugh changes:
- 0.10.1's fixes are to a node with a schedule, which Lugh does not run yet (P8), and to `tools/ci.sh install-debs`,
  which Lugh does not use; `MemoryStore::each_held` is P8's to take.
- 0.10.2's fix, a worker's mark cleared however a request's run ends, is inside Dannan's scheduler, which Lugh does not
  drive yet. `SteppedTime(poll)` is for a fixture that wrapped `SteppedTime` to coarsen its waits; Lugh's tests use it
  unwrapped, at its default, and keep it unless TSan shows a stall.

lir::mqtt moves from the commit d36356d to its first release, 0.1.0. The codec is the same; Lir's release adds its
installed CMake package, fuzz targets and Debian packages, none of which Lugh's fetched build uses. Dagda stays at 0.3.2
for the tests: 0.3.3 bounds repair's memory, which Lugh's tests do not exercise.

### Changed (breaking)

- Four flags and environment variables take the stack's config names (Dannan's `docs/config.md`: the flag and the
  variable are made from the whole dotted key). The old names are gone, not aliased:

  | Setting | Was | Now |
  |---|---|---|
  | `server.address` | `--address`, `LUGH_ADDRESS` | `--server-address`, `LUGH_SERVER_ADDRESS` |
  | `server.port` | `--port`, `LUGH_PORT` | `--server-port`, `LUGH_SERVER_PORT` |
  | `oauth.issuer` | `--issuer`, `LUGH_ISSUER` | `--oauth-issuer`, `LUGH_OAUTH_ISSUER` |
  | `oauth.mtls_port` | `--mtls-port`, `LUGH_MTLS_PORT` | `--oauth-mtls-port`, `LUGH_OAUTH_MTLS_PORT` |

  The YAML keys do not change. The packaged unit passes `--server-port 443`; a unit or script of your own that passes
  an old flag must be changed, or the node refuses to start, naming the flag.

### Tests

- Five `TokenSource` cases moved here from Louhi, which now uses `TokenSource` in place of its own service token: never
  fetched again sooner than `kLeastRefresh`, failed discovery retried on the back-off, no scopes sends no `scope`, a
  pending refresh asks nothing after `stop()`, and a source let go is not kept alive by its timer. A relying party that
  kept such tests of its own can drop them.

## 0.3.0: onto Dannan 0.10.0 (2026-11-20)

A release for source dependants, who fetch Lugh with FetchContent. Its Debian package is built and published once
Dagda 0.4.0, on Dannan 0.10.0, is in the apt repository: until then, a package build would test against Dagda 0.3.2's
packages, which are built on Dannan 0.9.2.

Repin: Dannan 0.9.2 to 0.10.0. From its release notes, Lugh takes `RetryPolicy::unbounded` now and moves onto the rest
in order (below). Dagda stays at 0.3.2 for the tests and lir::mqtt at d36356d; neither changed anything in Lugh.

### Changed

- Built against Dannan 0.10.0. It is a new minor, so the ABI changes: a dependant passing its own Dannan to lugh_client
  moves to 0.10.0 with it. Dagda 0.3.2 serves the tests: its request for Dannan 0.9.2 is met by the fetched 0.10.0, and
  its code compiles unchanged. The package will depend on `libdannan0.10`.
- A sanitizer build passes its sanitizer to Dannan as `DANNAN_SANITIZE`.
- `TokenSource` retries with Dannan's `RetryPolicy::unbounded`, the policy it wrote by hand before; it behaves as before.
- From Dannan's release notes, Lugh moves next onto Dannan's callback vocabulary, encodings, SHA-1, `RandomId`,
  `Prefix` and `RecordingSink`, each in its own step (`TODO/ACTIVE.md`). The first changes lugh_client's public types.
- Coming in 0.4.0: four flags and variables take the stack's config names (Dannan's `docs/config.md`): `--address`,
  `--port`, `--issuer` and `--mtls-port` become `--server-address`, `--server-port`, `--oauth-issuer` and
  `--oauth-mtls-port`, and `LUGH_ADDRESS` and the rest likewise.

### Fixed

- CodeQL failed from 0.2.0 on: its workflow did not check out Lir beside Dannan and Dagda.

## 0.2.0: packaged, and lugh_client for relying parties (2026-11-20)

Built against Dannan 0.9.2, Dagda 0.3.2 (the tests only) and lir::mqtt at d36356d (the tests and `lugh::client_topics`
only).

### For relying parties: what to use in place of your own code

`lugh_client` (`lugh::client`), fetched with `LUGH_BUILD_NODE=OFF`, passing your own Dannan. It fetches nothing else
([docs/client.md](docs/client.md)).

- **`RelyingParty`** (`lugh/client/relying_party.h`). It verifies Lugh's access tokens offline for one audience, against
  each trusted issuer's keys, which it fetches ahead of time. Use `verify_header(Authorization)`, or `verify(token)` with
  `status()` per issuer. Construct it with an `io_context`, which makes its own HTTPS client, or with your own `Https`.
- **`TokenSource`** (`relying_party.h`). A service's client-credentials token: fetched at start, refreshed at two thirds
  of its life, failing over across issuers, with a back-off that never parks. `current()` and `status()`.
- **`bearer_token(authorization)`**. The token from an `Authorization: Bearer` header: the scheme in any case,
  b64token characters only, at most 16 KiB.
- **`discover(https, issuer, ...)`**. An issuer's OpenID metadata, refused when it names another issuer.
- **`testing::FakeHttps`** (`lugh/client/testing.h`). A thread-safe `Https` for tests:
  - canned answers per URL, queued ones, and `forget_answers`;
  - a request held until the test lets it go (`hold`, `let_go`, `release`);
  - what was sent, read back (`sent`, `sent_to`, `header`).
- **`TopicGrants`** (`lugh/client/scopes.h`). Lir's topic scopes (`lir:pub`, `lir:sub`, `lir:retain`) parsed from a
  token's scopes, with `{sub}` replaced by the token's subject; it says why it refused each scope it refused.
- **`lugh::client_topics`** (`lugh/client/topics.h`): `may_publish` and `may_subscribe` against those grants, on Lir's
  MQTT codec, for a broker. Built only where `lir::mqtt` exists.

### Added

- **OAuth 2 and OpenID Connect** (P6, [docs/oauth.md](docs/oauth.md)). Registered applications sign people in with:
  - the authorization code flow with PKCE, client credentials, refresh tokens rotated with reuse detection, and the
    device grant;
  - PAR, DPoP, and mTLS client authentication with certificate-bound tokens;
  - introspection, revocation, discovery and JWKS;
  - ID tokens, userinfo, `acr` and `amr`, step-up, consent for third parties;
  - RP-initiated and back-channel logout;
  - opaque access tokens, and app passwords.
- **LDAP** (P9, [docs/ldap.md](docs/ldap.md)): LDAPS and StartTLS, bind, search with paging, compare, the writes mapped
  onto Lugh's fields, the password modify operation, POSIX numbers, and optional anonymous bind.
- **The dashboard** (P7): React, same-origin, served by the node. Users, groups, policies, applications, keys and the
  audit log, and everyone's own factors, sessions and app passwords; administering needs a passkey sign-in.
- **WebAuthn** (P11): passkeys and security keys (ES256, EdDSA, RS256), a passkey signing in alone, and the
  phishing-resistant level `phr`.
- **A person's own factors**: adding and removing factors behind a re-authentication window.
- **lugh_client** (P10): the `Verifier`, the HTTPS key source, the OAuth client (the code flow, client credentials, the
  device flow, refresh, introspection, revocation, PAR, DPoP, mTLS), the management API client, and the relying-party
  pieces above.
- **Hardening** (P12): libFuzzer targets for every parser of untrusted bytes, the systemd sandbox, key rotation drills,
  and a threat model ([docs/threat-model.md](docs/threat-model.md)).
- The listeners on Dannan's public listener and outbound connector, and the client address from Dannan's
  `forwarded_for`.
- The Debian package `lugh` ([docs/packaging.md](docs/packaging.md)):
  - `tools/build-deb.sh`, with the version from `git describe`;
  - the service installed disabled, the `lugh` user made by sysusers, and `/etc/lugh/config.yaml` as a conffile;
  - the dashboard in `/usr/share/lugh/dashboard`;
  - `lugh-node(8)`;
  - built against the installed `libdannan-dev`, so it depends on `libdannan0.9` and bundles nothing.
- The CMake options `LUGH_INSTALL_LAYOUT` (`local` or `debian`) and `LUGH_SYSTEM_DEPENDENCIES` (build against the
  installed Dannan, Dagda and Lir). A sanitizer build refuses the installed libraries.
- P8.0: Dagda fetched beside Dannan, and `ClusterRig`, which runs Lugh's spaces on Dagda's in-process cluster (the
  tests only; the node does not link Dagda yet).
- OpenLDAP's libldap as a test client against the real `lugh-node`: LDAPS, StartTLS, paged search, compare, the writes,
  and the password modify operation.
- CI on GitHub (GCC on x86-64 and arm64, clang), CodeQL, coverage to Codecov, and clang-tidy's
  `bugprone-use-after-move` over Lugh's own files.
- `CODE_OF_CONDUCT.md`, the Contributor Covenant 2.1.
- Test coverage of Lugh's own code: 98.7% of lines and 70.0% of branches, with compiler-made branches filtered out.

### Changed

- The README is about installing and using Lugh; why it exists moved to [docs/architecture.md](docs/architecture.md).
  Every project of the stack is linked by its GitHub URL.
- The binary's default configuration is the install layout's: `/etc/lugh/config.yaml` for the package, and
  `/usr/local/etc/lugh/config.yaml` for a local install.
- The topic-scope grammar moved from the node into lugh_client; the node grants by the same code.
- An app password may contain any character, the dot included. Lugh promises nothing about a password's characters.
- Raven, Alpine and OpenRC are gone: Debian with systemd only.

### Fixed

- **A user, group or application was stored with every string empty when built with GCC on x86-64.** Each was encoded
  in the same call that moved it into a callback, and that compiler evaluates the arguments right to left. Its records
  are now encoded before the call.
- The sign-in's back-off page said "Wait 1 seconds".
- A test certificate named its host only in the CN, which a real client (libldap) refuses. It now carries
  subjectAltName.
- `TokenSource` fetched on any timer wake, but a stepped time source wakes early by design.
- A relying party fetching lugh_client alone also fetched Lir.
- Two test files used `std::search` without including `<algorithm>`.

## 0.1.0: the directory, sign-in and the management API (2026-11-04)

The first release, aligned with Dannan 0.3.0 and the stack's conventions.

### Added

- The directory: people and services, groups and memberships, unique names and addresses, and final removal with
  tombstones.
- Sign-in:
  - Argon2id passwords with a breached-password list;
  - TOTP with replay refused;
  - recovery codes;
  - enrolment by a one-time link;
  - per-group policy (`pwd`, `mfa`);
  - back-off per account and per address.
- Genesis: `lugh-node init` makes the keyring, the master key (a systemd credential, or a passphrase) and root, whose
  password is shown once.
- The audit log, with entries chained by hash.
- The management API, `/api/v1`: JSON, scoped permissions, ETags, and one error shape.
- The sealed store and keyring on one node, interim until Dagda.
- TLS 1.3 only, with no plaintext listener; secrets in locked memory, wiped when freed.
