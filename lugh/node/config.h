//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "cli.h"
#include "core/status.h"
#include "loggers/logger.h"
#include "network/cidr.h"
#include "system/environment.h"

namespace lugh {

// Everything the service is told at start. Public fields, as blackraven-admin's Config: it
// is data, filled once by ConfigLoader and read by main. The master key is not here and
// never will be; it arrives as a systemd credential, or is typed.
struct Config {
  // The file read, empty when the defaults alone were used.
  std::string path;

  loggers::LogLevel log_level = loggers::INFO;
  loggers::LogFormat log_format = loggers::LogFormat::Text;

  std::string address = "0.0.0.0";
  std::uint16_t port = 8443;
  unsigned threads = 2;

  // Both required to serve: there is no plaintext listener. `lugh init` needs neither.
  std::string tls_certificate;
  std::string tls_key;

  // Where the node keeps what is its own: the keyring now, the store from P3. systemd makes
  // it, 0700 and owned by lugh; the unit names it.
  std::string state_directory = "/var/lib/lugh";

  // A list of passwords no one may set, one per line. Empty: none.
  std::string breached_passwords;

  // A request from one of these is taken at the last X-Forwarded-For entry; everything else
  // at its socket's address. Empty by default: no proxy is trusted until named.
  std::vector<network::Cidr> trusted_proxies;
};

class ConfigLoader {
 public:
  static constexpr const char* kInstalledPath = "/usr/local/etc/lugh/config.yaml";

  // default_path is read when neither --config nor $LUGH_CONFIG names a file, and only if
  // it exists; empty reads nothing.
  ConfigLoader(std::shared_ptr<system::Environment> environment, std::string default_path);

  // The defaults, then the file, then secrets.yaml beside it, then the environment, then
  // the command line, each overriding the one before. A value that cannot be used is an
  // error, never a silent default.
  Result<Config> load(const cli::Options& options);

  // Keys present in a file that nothing reads: a misspelling, most likely. For the log.
  const std::vector<std::string>& warnings() const { return _warnings; }

 private:
  Status _apply_file(Config& config, const std::string& path);
  Status _apply(Config& config, const std::string& key, const std::string& value, const std::string& source);

  std::shared_ptr<system::Environment> _environment;
  std::string _default_path;
  std::vector<std::string> _warnings;
};

}  // namespace lugh
