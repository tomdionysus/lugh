# Lugh - The Directory

[![Release](https://img.shields.io/github/v/tag/tomdionysus/lugh?sort=semver&label=release)](https://github.com/tomdionysus/lugh/tags)
[![CI](https://github.com/tomdionysus/lugh/actions/workflows/ci.yml/badge.svg)](https://github.com/tomdionysus/lugh/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/tomdionysus/lugh/graph/badge.svg)](https://codecov.io/gh/tomdionysus/lugh)
[![CodeQL](https://github.com/tomdionysus/lugh/actions/workflows/codeql.yml/badge.svg)](https://github.com/tomdionysus/lugh/actions/workflows/codeql.yml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

Lugh is the directory and single sign-on for a cluster of trusted machines. It is a C++20
service that holds the identities of people and services, signs them in with two factors,
and tells every other system who someone is and what they may do: through OAuth 2 and
OpenID Connect for applications, a management API and dashboard for administrators, LDAP
for software that knows nothing else, and a C++ library that makes a project a relying
party in a few lines. Why it exists, and how it works: [docs/architecture.md](docs/architecture.md).

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
- **LDAP.** A second front end on the same directory for mail servers, NAS boxes, VPNs and
  PAM: bind, search and compare, and writes mapped onto Lugh's own fields, never a general
  LDAP server ([docs/ldap.md](docs/ldap.md)).
- **A C++ library.** `lugh_client`, with `lugh::client::RelyingParty`: the code flow, token
  verification against cached JWKS, back-channel logout, and the client credentials and
  device flows, for a project that links Lugh as a subproject ([docs/client.md](docs/client.md)).
- **Audit.** The hash-chained log, verifiable end to end, exportable to a SIEM.

Everything in flight is TLS 1.3; there is no plaintext listener. Secrets live in locked
memory and are wiped when freed; a secret passed to a log call does not compile.

## Install

Lugh is packaged for Debian 13 (trixie), arm64 and x86-64. Dannan's shared library, which it
links, comes from the tomcully.com apt repository; Lugh's own package is built from a release tag
([docs/packaging.md](docs/packaging.md)):

```bash
sudo curl -fsSLo /etc/apt/sources.list.d/tomcully.sources https://tomcully.com/apt/tomcully.sources
sudo apt update
git clone --branch 0.2.0 https://github.com/tomdionysus/lugh.git && cd lugh
sudo apt build-dep ./ && tools/build-deb.sh
sudo apt install ./build-deb/lugh_0.2.0_*.deb
```

The package installs `lugh-node`, the configuration in `/etc/lugh`, the dashboard and the
systemd unit, and makes the `lugh` system user. The service is installed **disabled**: it needs
a certificate and a keyring first.

## Set up a node

1. **The certificate.** Put the node's TLS pair in `/etc/lugh/tls/` as `cert.pem` and `key.pem`,
   readable by the `lugh` group. Lugh speaks TLS 1.3 only; there is no plaintext listener.

2. **The keyring and the master key.** Once per node, make the keyring and seal the master key
   with `systemd-creds`, to the TPM where there is one. The key passes through the pipe and is
   never on disk in clear:

   ```bash
   sudo -u lugh lugh-node init --state-directory /var/lib/lugh \
     | sudo systemd-creds encrypt --name=lugh-master-key - /etc/credstore.encrypted/lugh-master-key
   ```

   If the encrypt step fails, remove `/var/lib/lugh/keyring` and run it again: init never
   replaces a keyring. On the first node this is the cluster's **genesis**: it also makes the
   user `root`, in the group `administrators`, with a random password that it shows once and
   keeps nowhere but as its hash.

3. **Start it.**

   ```bash
   sudo systemctl enable --now lugh
   curl -s https://<host>/health        # {"status":"ok"}
   ```

The unit runs as `lugh` on port 443 with `CAP_NET_BIND_SERVICE` and nothing else, writing only to
`/var/lib/lugh`. `systemctl reload lugh` reads renewed certificate files again.

## Use

- **Sign in.** Browse to `https://<host>/`. Root's first sign-in goes from the genesis password
  straight to enrolling a second factor (an authenticator app, or a passkey or security key);
  after that root signs in as anyone does and makes every other administrator. Everyone else
  enrols from a one-time link an administrator issues, so no administrator ever sees or sets a
  password.
- **The dashboard** at `https://<host>/` manages users, groups, policies, applications, keys and
  the audit log, and everyone's own factors, sessions and app passwords. Administering needs a
  passkey sign-in.
- **The management API** is `/api/v1`, for a session or an OAuth access token with the right
  scopes ([docs/api.md](docs/api.md)).
- **Applications** sign people in with OAuth 2 and OpenID Connect: register each one in the
  dashboard with its exact redirect URIs, the groups that may use it and the roles it maps them
  to. Discovery is at `/.well-known/openid-configuration` once `oauth.issuer` is set
  ([docs/oauth.md](docs/oauth.md)).
- **LDAP** for mail servers, NAS boxes, VPNs and PAM: set `ldap.port` (LDAPS) or
  `ldap.starttls_port`, and `ldap.base_dn` ([docs/ldap.md](docs/ldap.md)).
- **A C++ relying party** links `lugh_client` to verify Lugh's tokens offline and run the flows
  ([docs/client.md](docs/client.md)).

## Configure

`/etc/lugh/config.yaml`, then `secrets.yaml` beside it, then `LUGH_*` environment variables,
then the command line, each overriding the one before; the unit sets the port and the installed
paths. `lugh-node --help` lists every setting. Unknown keys are warned about and bad values
refused, naming their source. The master key is in none of them: it is the systemd credential
`lugh-master-key`, or a passphrase typed at start (`lugh-node init --passphrase`).

## Build from source

A C++20 compiler, CMake 3.24 or later, Boost 1.83 or newer, OpenSSL 3, yaml-cpp, GoogleTest
and libldap (for the tests). Dannan, Dagda and Lir are fetched from sibling checkouts at their
pinned releases (`CMakeLists.txt`):

```bash
cmake --preset debug && cmake --build build -j8
./build/lugh_tests
```

For a development node on port 8443 with a self-signed certificate for `localhost`:

```bash
tools/lugh_dev_cert.sh && tools/lugh_dev_init.sh
CREDENTIALS_DIRECTORY=config/dev/credentials ./build/lugh-node --config config/config.yaml
```

The dashboard is in `dashboard/` (`npm ci && npm run build`). [CONTRIBUTING.md](CONTRIBUTING.md)
has the conventions, the presets (`asan`, `tsan`, `fuzz`) and the tests.

## The stack

Lugh is one of a stack of projects written to one set of conventions, with no code duplicated
between them:

- [Dannan](https://github.com/tomdionysus/dannan), the network layer, which Lugh links.
- [Dagda](https://github.com/tomdionysus/dagda), the store, which Lugh's state moves onto next.
- [Lir](https://github.com/tomdionysus/lir), the MQTT broker, whose topic scopes Lugh grants.

Lugh signs people in for [Louhi](https://github.com/tomdionysus/louhi),
[Mimir](https://github.com/tomdionysus/mimir), [Kvasir](https://github.com/tomdionysus/kvasir),
[Macha](https://github.com/tomdionysus/macha) and
[AthenaSIP](https://github.com/blackravenltd/athenasip). What each project owns:
[Dagda's stack document](https://github.com/tomdionysus/dagda/blob/develop/TODO/2026-11-03-stack.md).

## Status

Version 0.2.0. Built and tested: the directory, sign-in with a second factor and WebAuthn, the
audit chain, the management API and the dashboard, genesis, OAuth 2 and OpenID Connect, writable
LDAP, `lugh_client`, and hardening: fuzzing, the sandbox, key rotation drills and a threat model
([docs/threat-model.md](docs/threat-model.md)). Each node is its own directory today; next, Lugh's
state moves onto Dagda so a cluster's nodes share one directory.

What each release changed: [CHANGELOG.md](CHANGELOG.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Everyone taking part follows the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Licence

Copyright (C) 2026 Tom Cully. Licensed under the GNU GPLv3; see `LICENSE`.
