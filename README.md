# Lugh - The Directory

Lugh is the directory and single sign-on for a cluster of trusted machines. It is a C++20
service that holds the identities of people and services, signs them in with two factors,
and tells every other system who someone is and what they may do: through OAuth 2 and
OpenID Connect for applications, a management API and dashboard for administrators, LDAP
for software that knows nothing else, and a C++ library that makes a project a relying
party in a few lines. It is the top of a stack: it runs on Dannan, the network, and keeps
everything it persists in Dagda, the store.

## Why it exists

Every system a person runs across their own machines ends up with the same unsolved
problem: who is this, and are they allowed? Each one answers it alone. Macha (a media
filesystem) has its own users and passwords; AthenaSIP (a SIP server) has realms and
digests; T.O.M.S and blackraven-admin each keep a session store and a login page. None of
them knows the others' users, a password changed in one is not changed in the rest, a
second factor is wherever someone got round to it, and removing a person means visiting
every system and hoping none was missed.

Lugh answers the question once:

- **One identity.** A person or a service is a principal, with a stable identifier that
  never changes and is never reused, in groups that say what they belong to. Every system
  keys its records on that identifier, not on a name or an address.
- **One sign-in.** A password and a second factor, checked in one place, with lockout and
  back-off that an attacker cannot turn into a denial of service. A browser signs in once
  and every allowed application follows, each asking only for what it has not yet seen.
- **One answer to "may they?"** Groups grant scopes; applications map groups to their own
  roles; Lugh is the source of every principal's scope, installed into Dannan's own check
  of who may write what.
- **One record.** Every sign-in, token, change and key operation is in an audit log whose
  entries chain by hash, so an edit or a deletion is detectable.
- **Nothing static.** A cluster is born with one credential, root's password, shown once
  and stored only as its hash. There is no bootstrap token, no key in a file, no setting
  that opens anything.

It is written for the Blackraven projects (T.O.M.S, blackraven-admin, Macha, AthenaSIP and
those that follow), but nothing in it is specific to them.

## What it does

- **Directory.** People and services, groups and membership, with names and addresses
  that are unique whatever their case. A removal is final: the identifier dies with a
  tombstone kept for ever.
- **Sign-in.** Argon2id passwords with a minimum length and a breached-password list; TOTP
  as the second factor, with replay refused; passkeys and security keys (WebAuthn: ES256,
  EdDSA and RS256), a passkey signing in alone with no name typed; recovery codes;
  enrolment by a one-time link, so no administrator ever sees or sets a password; policy
  per group saying how sure Lugh must be of a person (`pwd`, `mfa`, or `phr`, phishing-
  resistant, which only WebAuthn reaches).
- **OAuth 2 and OpenID Connect.** Authorisation code with PKCE, client
  credentials, refresh rotation and the device grant; PAR, DPoP and mTLS binding;
  introspection, revocation, discovery and JWKS; ID tokens, userinfo, `acr` and `amr`,
  step-up, and RP-initiated and back-channel logout. No implicit grant, no password grant.
  Only registered applications may send a user to sign in, and Lugh redirects only to an
  address it has on file.
- **Management API.** `/api/v1` for users, groups, memberships, factors, enrolment links,
  policies and the audit log: JSON, scoped permissions, ETags, and one error shape
  ([docs/api.md](docs/api.md)).
- **Dashboard.** A React admin interface (`dashboard/`) on the same API, same-origin, with no
  token in the browser, served by the node from `static.directory`. Everyone manages their own
  factors, sessions and app passwords there; administering needs a passkey sign-in.
- **LDAP** (planned). A second front end on the same directory for mail servers, NAS boxes,
  VPNs and PAM: bind, search and compare, and writes mapped onto Lugh's own fields, never
  a general LDAP server ([TODO/2026-11-04-ldap.md](TODO/2026-11-04-ldap.md)).
- **A C++ library** (planned). `lugh::client::RelyingParty`: the code flow, token
  verification against cached JWKS, back-channel logout, and the client credentials and
  device flows, for a project that links Lugh as a subproject.
- **Audit.** The hash-chained log, verifiable end to end, exportable to a SIEM.

Everything in flight is TLS 1.3; there is no plaintext listener. Secrets live in locked
memory and are wiped when freed; a secret passed to a log call does not compile.

## The stack

Lugh is one of four projects written to one set of conventions, each its own library and
repository, with no code duplicated between them: a piece needed by more than one lives in
exactly one, and the others link it.

```
   Lugh            Lir             Macha, AthenaSIP, ...      hosted systems
     |               |                  |
   Dagda: the store  (domains, sealing, objects, heads, leases)
     |
   Dannan: the network  (reachability, routes, channels, membership,
                         identity, placement, work classes, status)
```

- **[Dannan](../dannan)** is the network: it makes a set of nodes, on any mix of home and
  rented machines and behind any NAT, behave as one network, and knows who the nodes are.
  Lugh takes from it the node, membership, the transport, node identity and key custody,
  the scope seam it fills, time, logging, secure memory, the signing and Argon2id
  primitives, durable files and the test fixtures. Lugh is pinned to a Dannan release in
  `CMakeLists.txt` and builds it into its own tree.
- **[Dagda](../dagda)** is the store: domains and their keys, sealing at rest, immutable
  objects, heads whose merge the owner supplies, leases and node-local spaces. Lugh's
  state will live there in two domains, `lugh/scope` on every node and `lugh/secrets` on
  Lugh's, under Lugh's own merge rules: a revocation is never undone by a merge, a
  credential change keeps the newest and revokes the losers' sessions, and a single-use
  grant is redeemed only where it was issued. Until Dagda carries Lugh's spaces, Lugh
  keeps an interim sealed store and keyring, frozen.
- **[Lir](../lir)** is the event system, a distributed multimaster MQTT broker on Dannan
  and Dagda. It never links Lugh; its authentication is pluggable, and a Lugh plugin is
  one option.

Hosted systems never address one another. They exchange frames through Dannan, share
state through Dagda, and learn who someone is from Lugh.

## How to use it

### Build

A C++20 compiler, CMake 3.23 or later, Boost 1.87 or newer (Asio, Beast and JSON), OpenSSL
3, yaml-cpp and GoogleTest. Dannan is fetched from `../dannan` at the pinned release.

```bash
cmake --preset debug && cmake --build build -j8
```

Warnings are errors and hardening is on by default. `--preset asan`, `--preset tsan` and
`--preset fuzz` (a clang with libFuzzer) are run at the end of every phase, not kept for
releases, because Lugh holds every credential.

### Run

Lugh needs a certificate before it will listen and a master key before it will serve:

```bash
tools/lugh_dev_cert.sh
tools/lugh_dev_init.sh
CREDENTIALS_DIRECTORY=config/dev/credentials ./build/lugh-node --config config/config.yaml
```

`lugh_dev_init.sh` runs `lugh-node init`, which makes the keyring in `config/dev/state`,
writes the master key where systemd would hand it over, and shows the root password once.
To type a passphrase at each start instead, run
`./build/lugh-node init --config config/config.yaml --passphrase` and leave
`CREDENTIALS_DIRECTORY` unset.

That listens on 8443 with a self-signed certificate for `localhost`. `GET /health` and
`GET /ready` are open and say nothing but that the service is up:

```bash
curl -sk https://localhost:8443/health
{"status":"ok"}
```

The management API is `/api/v1` ([docs/api.md](docs/api.md)). Nothing opens it yet:
callers are resolved from sessions and OAuth tokens, which arrive with OAuth, so until then
it answers 401 to everyone.

### Make a project a relying party

Once the library ships, a C++ project adds Lugh as a subproject and uses
`lugh::client::RelyingParty` for the code flow, the callback, token verification and
back-channel logout; an application is registered with Lugh by an administrator, with
exact redirect URIs, the groups that may use it and the roles it maps them to. The design
is in [docs/architecture.md](docs/architecture.md), "Single sign-on".

### Test

```bash
./build/lugh_tests                           # the units, the IoC check, and the init,
                                             # shutdown and API tests on the real binary
ctest --test-dir build --output-on-failure   # the same, as the install's gate
```

Tests are GoogleTest only, in one binary. Time is injected and stepped, never slept.

### Deploy

Not yet: the first install on a node follows hosting on Dannan and Dagda. The shape: get
the tree onto the node, build there, `ctest`, put the certificate pair in
`/usr/local/etc/lugh/tls/`, then `sudo cmake --install build-release`, which installs the
binary, config and docs, runs `deploy/host-setup.sh`, and enables and restarts
`lugh.service`. The unit runs as its own user, `lugh`, on 443 with `CAP_NET_BIND_SERVICE`
and nothing else, writing only to `/var/lib/lugh`.

On a new node, once, make the keyring and seal the master key with `systemd-creds`, to the
TPM where there is one. The key passes through the pipe and is never on disk in clear:

```bash
sudo -u lugh /usr/local/bin/lugh-node init --config /usr/local/etc/lugh/config.yaml \
    --state-directory /var/lib/lugh \
  | sudo systemd-creds encrypt --name=lugh-master-key - /etc/credstore.encrypted/lugh-master-key
sudo systemctl restart lugh
```

The unit loads it with `LoadCredentialEncrypted=`. If the encrypt step fails, remove
`/var/lib/lugh/keyring` and run it again: init never replaces a keyring.

`lugh-node init` on the first node is the cluster's **genesis**: it also makes the user
`root`, in the group `administrators`, with a random password that it shows once and keeps
nowhere but as its hash. Root's first sign-in goes from that password straight to enrolling
a second factor; after that root signs in as anyone does, and makes every other
administrator.

### Configure

`config/config.yaml`, then `secrets.yaml` beside it, then `LUGH_*` environment variables,
then the command line, each overriding the one before. `--help` lists them. Unknown keys
are warned about and bad values refused, naming their source. The master key is in none of
them: it is the systemd credential `lugh-master-key`, or a passphrase typed at start.

## Repository layout

```text
lugh/<subsystem>/   the library: headers and sources side by side
lugh/test/          GoogleTest, flat, one binary (lugh_tests); fixtures in lugh/test/fixtures/
lugh/fuzz/          libFuzzer targets, one per parser of untrusted bytes
tools/              lugh-node (the service), the development certificate and keyring
config/             config.yaml, no secrets
deploy/             the systemd unit and host setup
docs/               how it works
TODO/               now and next (ACTIVE.md), designs, and what shipped (COMPLETED.md)
```

Design: [docs/architecture.md](docs/architecture.md). Conventions, shared with the stack:
[CONTRIBUTING.md](CONTRIBUTING.md). What was taken from the earlier projects:
[docs/provenance.md](docs/provenance.md). What each project of the stack owns:
`../dagda/TODO/2026-11-03-stack.md`.

## Status

Version 0.1.0 is tagged; `develop` is ahead of it. Built and tested: the directory,
sign-in with the second factor and WebAuthn, the audit chain, the management API, genesis,
OAuth 2 and OpenID Connect, writable LDAP, `lugh_client`, the listeners on Dannan's, and
the interim sealed store and keyring (Lugh is in Dannan's callback shape above the frozen
store, links Dannan for every shared primitive, and has no copy of one). Next: hosting on
Dannan's `Context` and Dagda, the dashboard, hardening, and the rollout to each project. Every phase ends green under ASan with UBSan and
under TSan.

## Licence

Copyright (C) 2026 Tom Cully. Licensed under the GNU GPLv3; see `LICENSE`.
