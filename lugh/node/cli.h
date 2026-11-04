//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <string>
#include <vector>

namespace lugh::cli {

// What the process is to do: serve, the default, or make a node's keyring and master key.
enum class Command { serve, init };

// The switches that say what the process does rather than how it is set up. Everything
// else on the command line, the command word and every setting's flag among it, is for
// Dannan's settings reader (lugh/node/config.h), which refuses what it does not know.
struct Options {
  // init only: a master key from a typed passphrase, for a host with no systemd credentials.
  bool passphrase = false;
  bool version = false;
  bool help = false;

  // The rest, in order.
  std::vector<std::string> arguments;
};

inline Options parse(int argc, char* argv[]) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string argument = argv[i];
    if (argument == "--version" || argument == "-v") {
      options.version = true;
    } else if (argument == "--help" || argument == "-h") {
      options.help = true;
    } else if (argument == "--passphrase") {
      options.passphrase = true;
    } else {
      options.arguments.push_back(argument);
    }
  }
  return options;
}

// The usage text, around `settings`, the reader's own account of the flags it takes
// (ConfigLoader::describe()).
inline std::string usage(const std::string& settings) {
  return "Usage: lugh-node [options]       serve\n"
         "       lugh-node init [options]  make this node's keyring and master key\n"
         "\n"
         "  -c, --config PATH        the configuration to read\n"
         "  --passphrase             init: derive the master key from a typed passphrase,\n"
         "                           for a host without systemd credentials\n"
         "  -v, --version            print the version and exit\n"
         "  -h, --help               print this and exit\n"
         "\n"
         "Settings, each from the configuration file, its environment variable or its flag:\n"
         "\n" +
         settings +
         "\n"
         "Settings are read in this order, each overriding the one before: the\n"
         "defaults, the configuration file, secrets.yaml beside it, the environment, then\n"
         "the command line.\n"
         "\n"
         "With no --config, the first of these that exists is read:\n"
         "\n"
         "  $LUGH_CONFIG\n"
         "  /usr/local/etc/lugh/config.yaml\n"
         "\n"
         "The master key is in none of these. `lugh-node init` writes a new one, 32 raw\n"
         "bytes, to standard output, which must not be a terminal; pipe it to\n"
         "\n"
         "  systemd-creds encrypt --name=lugh-master-key - \\\n"
         "      /etc/credstore.encrypted/lugh-master-key\n"
         "\n"
         "and the unit loads it as the credential lugh-master-key. With --passphrase,\n"
         "init asks for a passphrase instead, and so does every start.\n";
}

}  // namespace lugh::cli
