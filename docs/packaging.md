# Packaging

Lugh is packaged for Debian trixie as `lugh` (the service, its configuration, the dashboard, the
systemd unit and these documents) and `lugh-dbgsym`. There is no `-dev` package yet: the installed
`lugh_client` package is still to come, and until then a relying party fetches Lugh into its own
build ([client.md](client.md)). The package is built with debhelper from `debian/`, driving the
CMake build; the CMake install rules decide where every file goes (`LUGH_INSTALL_LAYOUT=debian`).

## Building

On Debian trixie, natively for the machine's architecture, from a git checkout, with Dannan's
development package installed (and Dagda's for the tests):

```sh
sudo apt install dpkg-dev
sudo apt build-dep ./
tools/build-deb.sh
```

The package is written to `build-deb/`. The dashboard is built inside the build (`npm ci` at the
top, the npm workspace of the dashboard and `@lugh/admin-ui`, which fetches their dependencies);
the tests run inside it too, and `DEB_BUILD_OPTIONS=nocheck` skips them.

## Dependencies

Lugh links Dannan's shared library from `libdannan0.12`, found by `${shlibs:Depends}`; nothing is
bundled. It is built against `libdannan-dev` (>= 0.12.1, << 0.13), and its tests against Dagda 0.4's
`libdagda-dev`. The tests also need Dagda
(`libdagda-dev`) and Lir's MQTT codec: Lir's installed package when there is one, otherwise Lir
fetched for the tests alone and never installed.

## Versions

The version comes from `git describe`. The tag `0.2.0` gives `0.2.0`; a build three commits later
gives `0.2.0+git3.gabc1234`, which sorts after `0.2.0` and before `0.2.1`; uncommitted changes add
`.dirty`. A build of a tag must match `project(lugh VERSION ...)` in `CMakeLists.txt`, or the
script refuses it. Only builds of a tag are released.

## What the package installs

| Path | What |
|---|---|
| `/usr/bin/lugh-node` | the service, and `lugh-node init` |
| `/etc/lugh/config.yaml` | the configuration, a conffile, readable by `lugh` only |
| `/etc/lugh/secrets.yaml` | made empty by the postinst if absent, never part of the package |
| `/etc/lugh/tls/` | for the operator's `cert.pem` and `key.pem` |
| `/usr/share/lugh/dashboard/` | the dashboard's build, served by the node |
| `/usr/lib/systemd/system/lugh.service` | the unit |
| `/usr/lib/sysusers.d/lugh.conf` | the `lugh` system user |
| `/var/lib/lugh/` | the keyring and the store, the one place the service writes |

## What the package does

- The configuration is a conffile, so an upgrade keeps local changes and asks before replacing a
  changed file.
- The service is installed disabled and not started: it needs a TLS pair and a keyring first. An
  upgrade restarts it if it is enabled or running.
- `apt remove` keeps `/etc/lugh`; `apt purge` deletes it. Neither touches `/var/lib/lugh` or the
  sealed master key in `/etc/credstore.encrypted`: they are the directory itself.
