#!/bin/sh
#
# Prepares a node for lugh. Run by `cmake --install`, as root, on every install; every step
# is safe to repeat. The certificate pair under /usr/local/etc/lugh/tls is the operator's
# to put there; this only sets who may read it.

set -eu

CONFDIR=/usr/local/etc/lugh

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
