# Lugh

*v0.1.0*

The authentication and directory server for the Blackraven projects, and their single
sign-on: one C++20 service and a React dashboard. It holds the identities of people and
services, signs them in with two factors, and issues OAuth 2 and OpenID Connect tokens
that T.O.M.S, blackraven-admin, Macha, AthenaSIP and whatever follows can trust. It offers a
management API, a read-only LDAP for software that knows nothing else, and a C++ library
that makes a project a relying party in a few lines. Several nodes form one cluster over a
replicated, sealed store built on Macha's technology.

Design: [docs/architecture.md](docs/architecture.md). Code style and what is lifted from
blackraven-admin, AthenaSIP and Macha: [docs/code-style.md](docs/code-style.md). What is
being worked on: [TODO/ACTIVE.md](TODO/ACTIVE.md); what shipped:
[TODO/COMPLETE.md](TODO/COMPLETE.md).

## Repository layout

```text
src/<subsystem>/  the service: headers and sources side by side, and main.cpp
config/           config.yaml, no secrets
deploy/           the systemd unit and host setup
tests/            GoogleTest, mirroring src/, and the shutdown test
fuzz/             libFuzzer targets, one per parser
scripts/          the IoC check and the development certificate
docs/             how it works
TODO/             now and next, and what shipped
```

## Build

Boost 1.87 or newer (Asio, Beast, JSON, all header-only), OpenSSL 3, yaml-cpp, GoogleTest,
Python 3 and a C++20 compiler.

```bash
cmake --preset debug && cmake --build build -j8
```

Warnings are errors and hardening is on, by default. `--preset asan`, `--preset tsan` and
`--preset fuzz` (which needs a clang with libFuzzer: on a Mac, Homebrew's) are part of
finishing a phase, not something kept for releases.

## Run

Lugh has no plaintext listener, so it needs a certificate before it will start:

```bash
scripts/dev-cert.sh
./build/lugh --config config/config.yaml
```

That listens on 8443 with a self-signed certificate for `localhost`. `GET /health` and
`GET /ready` are open and always JSON, and say nothing but that the service is up:

```bash
curl -sk https://localhost:8443/health
{"status":"ok"}
```

## Test

```bash
./build/lugh_tests                           # the unit suite
ctest --test-dir build --output-on-failure   # that, the shutdown test and the IoC check
```

## Deploy

Not yet: the first install on a node is after P8, on the maintainer's word. The shape, as
blackraven-admin: get the tree onto the node, build there, `ctest`, put the certificate
pair in `/usr/local/etc/lugh/tls/`, then `sudo cmake --install build-release`, which
installs the binary, config and docs, runs `deploy/host-setup.sh`, and enables and restarts
`lugh.service`. The unit runs as its own user, `lugh`, on port 443 with
`CAP_NET_BIND_SERVICE` and nothing else, writing only to `/var/lib/lugh`.

## Configuration

`config/config.yaml`, then `secrets.yaml` beside it, then `LUGH_*` environment variables,
then the command line, each overriding the one before. `--help` lists them. The master key
is in none of them.
