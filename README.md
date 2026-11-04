# Lugh

*v0.1.0*

The authentication and directory server for the Blackraven projects, and their single
sign-on: one C++20 service and a React dashboard. It holds the identities of people and
services, signs them in with two factors, and issues OAuth 2 and OpenID Connect tokens
that T.O.M.S, blackraven-admin, Macha, AthenaSIP and whatever follows can trust. It offers a
management API, a read-only LDAP for software that knows nothing else, and a C++ library
that makes a project a relying party in a few lines. Several nodes form one cluster over a
replicated, sealed store built on Macha's technology.

Design: [docs/architecture.md](docs/architecture.md). Conventions, shared with Dannan and
Dagda: [CONTRIBUTING.md](CONTRIBUTING.md). What was lifted from blackraven-admin,
AthenaSIP and Macha: [docs/provenance.md](docs/provenance.md). What is
being worked on: [TODO/ACTIVE.md](TODO/ACTIVE.md); what shipped:
[TODO/COMPLETED.md](TODO/COMPLETED.md).

## Repository layout

```text
lugh/<subsystem>/   the library: headers and sources side by side
lugh/include/lugh/  the public headers
lugh/test/          GoogleTest, flat, one binary (lugh_tests); fixtures in lugh/test/fixtures/
lugh/fuzz/          libFuzzer targets, one per parser of untrusted bytes
tools/              lugh-node (the service), the IoC check, the development certificate and keyring
test/process/       the real binary's tests: shutdown, init, the API
config/             config.yaml, no secrets
deploy/             the systemd unit and host setup
docs/               how it works
TODO/               now and next (ACTIVE.md), and what shipped (COMPLETED.md)
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

Lugh has no plaintext listener, so it needs a certificate before it will start, and it
opens its keyring before it serves, so it needs a master key too:

```bash
tools/lugh_dev_cert.sh
tools/lugh_dev_init.sh
CREDENTIALS_DIRECTORY=config/dev/credentials ./build/lugh-node --config config/config.yaml
```

`dev-init.sh` runs `lugh-node init`, which makes the keyring in `config/dev/state`, writes the
master key where systemd would hand it over, and shows the development root password. To type a passphrase at each start instead,
run `./build/lugh-node init --config config/config.yaml --passphrase` and leave
`CREDENTIALS_DIRECTORY` unset.

That listens on 8443 with a self-signed certificate for `localhost`. `GET /health` and
`GET /ready` are open and always JSON, and say nothing but that the service is up:

```bash
curl -sk https://localhost:8443/health
{"status":"ok"}
```

The management API is `/api/v1` (users, groups, memberships, factors, enrolment links,
policies and the audit log; [docs/api.md](docs/api.md)). Nothing opens it yet: callers are
resolved from sessions and OAuth tokens, which arrive in P6, so until then it answers 401
to everyone.

## Test

```bash
./build/lugh_tests                           # the unit suite
ctest --test-dir build --output-on-failure   # that, the shutdown, init and API tests, and the IoC check
```

## Deploy

Not yet: the first install on a node is after P8, on the maintainer's word. The shape, as
blackraven-admin: get the tree onto the node, build there, `ctest`, put the certificate
pair in `/usr/local/etc/lugh/tls/`, then `sudo cmake --install build-release`, which
installs the binary, config and docs, runs `deploy/host-setup.sh`, and enables and restarts
`lugh.service`. The unit runs as its own user, `lugh`, on port 443 with
`CAP_NET_BIND_SERVICE` and nothing else, writing only to `/var/lib/lugh`.

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

`lugh-node init` on the first node is the cluster's **genesis**: it also makes the user `root`,
in the group `administrators`, with a random password that it shows once on standard error
and keeps nowhere but as its hash. That password is the only credential Lugh is born with:
there is no token, key or setting that opens it. Root's first sign-in (P6) goes from that
password straight to enrolling a second factor; after that root signs in as anyone does,
and makes every other administrator.

## Configuration

`config/config.yaml`, then `secrets.yaml` beside it, then `LUGH_*` environment variables,
then the command line, each overriding the one before. `--help` lists them. The master key
is in none of them: it is the systemd credential `lugh-master-key`, or a passphrase typed
at start.
