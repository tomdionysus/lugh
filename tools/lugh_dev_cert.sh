#!/bin/sh
#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

#
# A self-signed certificate for development, where config/config.yaml expects it. Lugh has
# no plaintext listener, so there is no running it without one. Safe to repeat: an existing
# pair is left alone unless --force is given.

set -eu

cd "$(dirname "$0")/.."
mkdir -p config/dev

if [ -f config/dev/cert.pem ] && [ "${1:-}" != "--force" ]; then
    echo "dev-cert: config/dev/cert.pem exists; --force replaces it"
    exit 0
fi

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
    -keyout config/dev/key.pem -out config/dev/cert.pem \
    -subj "/CN=localhost" -days 30 \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null

chmod 0600 config/dev/key.pem
echo "dev-cert: wrote config/dev/cert.pem and config/dev/key.pem (30 days, CN=localhost)"
