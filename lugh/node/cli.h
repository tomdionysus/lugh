//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <string>

namespace lugh::cli {

// What the process is to do: serve, the default, or make a node's keyring and master key.
enum class Command { serve, init };

// The parsed command line. Values are kept as given; the configuration loader checks them,
// so a bad --port and a bad server.port are refused with the same words.
struct Options {
  Command command = Command::serve;

  // Empty: $LUGH_CONFIG, then the installed path, then the defaults alone.
  std::string config;

  std::string address;
  std::string port;
  std::string tls_certificate;
  std::string tls_key;
  std::string log_level;
  std::string log_format;
  std::string state_directory;

  // init only: a master key from a typed passphrase, for a host with no systemd credentials.
  bool passphrase = false;

  bool version = false;
  bool help = false;

  // False stops the service before it starts. An unknown argument is an error, never ignored.
  bool ok = true;
  std::string error;
};

inline Options parse(int argc, char* argv[]) {
  Options options;
  bool named_command = false;

  for (int i = 1; i < argc && options.ok; ++i) {
    const std::string argument = argv[i];

    // Accepts both --name value and --name=value.
    const auto takes = [&](const std::string& name, const std::string& what, std::string& out) -> bool {
      if (argument == name) {
        if (i + 1 >= argc) {
          options.ok = false;
          options.error = name + " needs " + what;
          return true;
        }

        out = argv[++i];
        if (out.empty()) {
          options.ok = false;
          options.error = name + " needs " + what;
        }
        return true;
      }

      const auto prefix = name + "=";
      if (argument.rfind(prefix, 0) == 0) {
        out = argument.substr(prefix.size());
        if (out.empty()) {
          options.ok = false;
          options.error = name + " needs " + what;
        }
        return true;
      }

      return false;
    };

    if (argument == "--version" || argument == "-v") {
      options.version = true;
    } else if (argument == "--help" || argument == "-h") {
      options.help = true;
    } else if (argument == "--passphrase") {
      options.passphrase = true;
    } else if (takes("--config", "a path", options.config) || takes("-c", "a path", options.config)) {
    } else if (takes("--address", "an address", options.address)) {
    } else if (takes("--port", "a port", options.port)) {
    } else if (takes("--tls-certificate", "a path", options.tls_certificate)) {
    } else if (takes("--tls-key", "a path", options.tls_key)) {
    } else if (takes("--log-level", "debug, info, warn or error", options.log_level)) {
    } else if (takes("--log-format", "text or json", options.log_format)) {
    } else if (takes("--state-directory", "a path", options.state_directory)) {
    } else if (!argument.empty() && argument[0] != '-') {
      options.ok = false;
      if (named_command) {
        options.error = "unexpected argument: " + argument;
      } else if (argument == "init") {
        options.ok = true;
        options.command = Command::init;
        named_command = true;
      } else {
        options.error = "unknown command: " + argument;
      }
    } else {
      options.ok = false;
      options.error = "unknown option: " + argument;
    }
  }

  if (options.ok && options.passphrase && options.command != Command::init) {
    options.ok = false;
    options.error = "--passphrase is for init";
  }

  return options;
}

inline std::string usage() {
  return "Usage: lugh [options]          serve\n"
         "       lugh init [options]     make this node's keyring and master key\n"
         "\n"
         "  -c, --config PATH        the configuration to read\n"
         "  --address ADDRESS        the address to listen on (server.address)\n"
         "  --port PORT              the port to listen on (server.port)\n"
         "  --tls-certificate PATH   the certificate chain, PEM (tls.certificate)\n"
         "  --tls-key PATH           its private key, PEM (tls.key)\n"
         "  --log-level LEVEL        debug, info, warn or error (log.level)\n"
         "  --log-format FORMAT      text or json (log.format)\n"
         "  --state-directory PATH   where the keyring is kept (state.directory)\n"
         "  --passphrase             init: derive the master key from a typed passphrase,\n"
         "                           for a host without systemd credentials\n"
         "  -v, --version            print the version and exit\n"
         "  -h, --help               print this and exit\n"
         "\n"
         "Settings are read in this order, each overriding the one before: the\n"
         "defaults, the configuration file, secrets.yaml beside it, the environment\n"
         "(LUGH_ADDRESS, LUGH_PORT, LUGH_TLS_CERTIFICATE, LUGH_TLS_KEY, LUGH_LOG_LEVEL,\n"
         "LUGH_LOG_FORMAT, LUGH_STATE_DIRECTORY), then the command line.\n"
         "\n"
         "With no --config, the first of these that exists is read:\n"
         "\n"
         "  $LUGH_CONFIG\n"
         "  /usr/local/etc/lugh/config.yaml\n"
         "\n"
         "The master key is in none of these. `lugh init` writes a new one, 32 raw\n"
         "bytes, to standard output, which must not be a terminal; pipe it to\n"
         "\n"
         "  systemd-creds encrypt --name=lugh-master-key - \\\n"
         "      /etc/credstore.encrypted/lugh-master-key\n"
         "\n"
         "and the unit loads it as the credential lugh-master-key. With --passphrase,\n"
         "init asks for a passphrase instead, and so does every start.\n";
}

}  // namespace lugh::cli
