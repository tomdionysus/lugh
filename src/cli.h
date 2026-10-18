#pragma once

#include <string>

namespace lugh::cli {

// The parsed command line. Values are kept as given; the configuration loader checks them,
// so a bad --port and a bad server.port are refused with the same words.
struct Options {
  // Empty: $LUGH_CONFIG, then the installed path, then the defaults alone.
  std::string config;

  std::string address;
  std::string port;
  std::string tls_certificate;
  std::string tls_key;
  std::string log_level;
  std::string log_format;

  bool version = false;
  bool help = false;

  // False stops the service before it starts. An unknown argument is an error, never ignored.
  bool ok = true;
  std::string error;
};

inline Options parse(int argc, char* argv[]) {
  Options options;

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
    } else if (takes("--config", "a path", options.config) || takes("-c", "a path", options.config)) {
    } else if (takes("--address", "an address", options.address)) {
    } else if (takes("--port", "a port", options.port)) {
    } else if (takes("--tls-certificate", "a path", options.tls_certificate)) {
    } else if (takes("--tls-key", "a path", options.tls_key)) {
    } else if (takes("--log-level", "debug, info, warn or error", options.log_level)) {
    } else if (takes("--log-format", "text or json", options.log_format)) {
    } else {
      options.ok = false;
      options.error = "unknown option: " + argument;
    }
  }

  return options;
}

inline std::string usage() {
  return "Usage: lugh [options]\n"
         "\n"
         "  -c, --config PATH        the configuration to read\n"
         "  --address ADDRESS        the address to listen on (server.address)\n"
         "  --port PORT              the port to listen on (server.port)\n"
         "  --tls-certificate PATH   the certificate chain, PEM (tls.certificate)\n"
         "  --tls-key PATH           its private key, PEM (tls.key)\n"
         "  --log-level LEVEL        debug, info, warn or error (log.level)\n"
         "  --log-format FORMAT      text or json (log.format)\n"
         "  -v, --version            print the version and exit\n"
         "  -h, --help               print this and exit\n"
         "\n"
         "Settings are read in this order, each overriding the one before: the\n"
         "defaults, the configuration file, secrets.yaml beside it, the environment\n"
         "(LUGH_ADDRESS, LUGH_PORT, LUGH_TLS_CERTIFICATE, LUGH_TLS_KEY, LUGH_LOG_LEVEL,\n"
         "LUGH_LOG_FORMAT), then the command line.\n"
         "\n"
         "With no --config, the first of these that exists is read:\n"
         "\n"
         "  $LUGH_CONFIG\n"
         "  /usr/local/etc/lugh/config.yaml\n";
}

}  // namespace lugh::cli
