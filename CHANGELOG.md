# Changelog

What each release added, changed and fixed, and what a project of the stack can now take from Lugh in place of its own
code. Newest first. The tags are on `main`.

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
