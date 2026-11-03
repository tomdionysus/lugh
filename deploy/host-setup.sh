#!/bin/sh
#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

#
# Prepares a node for lugh. Run by `cmake --install`, as root, on every install; every step
# is safe to repeat. The certificate pair under /usr/local/etc/lugh/tls and the master key
# credential are the operator's to put there; this only sets who may read them.

set -eu

CONFDIR=/usr/local/etc/lugh
STATEDIR=/var/lib/lugh
CREDSTORE=/etc/credstore.encrypted

# The service's own user: no login, no home.
if ! getent group lugh >/dev/null; then
    groupadd --system lugh
    echo "host-setup: created group lugh"
fi

if ! getent passwd lugh >/dev/null; then
    useradd --system --gid lugh --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin lugh
    echo "host-setup: created user lugh"
fi

# The config is readable by the service and nobody else; secrets.yaml, when there is one,
# the same.
chown root:lugh "$CONFDIR"
chmod 0750 "$CONFDIR"
chown root:lugh "$CONFDIR/config.yaml"
chmod 0640 "$CONFDIR/config.yaml"
if [ -f "$CONFDIR/secrets.yaml" ]; then
    chown root:lugh "$CONFDIR/secrets.yaml"
    chmod 0640 "$CONFDIR/secrets.yaml"
fi

# The TLS pair: the key readable by the service only.
mkdir -p "$CONFDIR/tls"
chown root:lugh "$CONFDIR/tls"
chmod 0750 "$CONFDIR/tls"
if [ -f "$CONFDIR/tls/key.pem" ]; then
    chown root:lugh "$CONFDIR/tls/cert.pem" "$CONFDIR/tls/key.pem"
    chmod 0644 "$CONFDIR/tls/cert.pem"
    chmod 0640 "$CONFDIR/tls/key.pem"
else
    echo "host-setup: WARNING: no $CONFDIR/tls/key.pem; put the certificate pair there before the service can start" >&2
fi

# The state directory, before the first start, so `lugh-node init` can make the keyring in it.
# systemd's StateDirectory= keeps it so afterwards.
mkdir -p "$STATEDIR"
chown lugh:lugh "$STATEDIR"
chmod 0700 "$STATEDIR"

# Where systemd-creds puts sealed credentials, readable by root alone: systemd decrypts the
# master key for the service at each start.
mkdir -p "$CREDSTORE"
chmod 0700 "$CREDSTORE"
if [ ! -f "$CREDSTORE/lugh-master-key" ]; then
    echo "host-setup: WARNING: no master key credential; run lugh-node init (see the README) before the service can start" >&2
fi
