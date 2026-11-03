#!/bin/sh
#
# Lugh - The Directory
#
# Copyright (C) 2026 Tom Cully <mail@tomcully.com>
# Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
#

#
# A keyring and master key for development, where config/config.yaml expects them: the
# keyring in config/dev/state, the master key in config/dev/credentials as systemd would
# hand it over. Genesis shows root's password once, on the terminal: copy it. Then:
#
#   CREDENTIALS_DIRECTORY=config/dev/credentials ./build/lugh-node --config config/config.yaml
#
# Safe to repeat: an existing keyring is left alone, because a new master key would not
# open it. Remove config/dev/state and config/dev/credentials to start again.

set -eu

cd "$(dirname "$0")/.."
LUGH=${LUGH:-./build/lugh-node}
umask 077

if [ -f config/dev/state/keyring ]; then
    echo "dev-init: config/dev/state/keyring exists; remove config/dev/state and config/dev/credentials to start again"
    exit 0
fi

mkdir -p config/dev/credentials
if ! "$LUGH" init --config config/config.yaml > config/dev/credentials/lugh-master-key.new; then
    rm -f config/dev/credentials/lugh-master-key.new
    exit 1
fi
mv config/dev/credentials/lugh-master-key.new config/dev/credentials/lugh-master-key
echo "dev-init: wrote config/dev/state/keyring and config/dev/credentials/lugh-master-key"
