//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "dannan/config/config.h"
#include "dannan/status/log.h"
#include "lugh/core/status.h"
#include "lugh/network/cidr.h"
#include "lugh/node/cli.h"
#include "lugh/system/environment.h"
#include "lugh/version.h"

namespace lugh {

// Everything the service is told at start. Public fields, as blackraven-admin's Config: it
// is data, filled once by ConfigLoader and read by main. The master key is not here and
// never will be; it arrives as a systemd credential, or is typed.
struct Config {
  // The command word: none is serve.
  cli::Command command = cli::Command::serve;

  // The file read, empty when the defaults alone were used.
  std::string path;

  dannan::status::LogLevel log_level = dannan::status::LogLevel::info;
  dannan::status::LogFormat log_format = dannan::status::LogFormat::text;

  std::string address = "0.0.0.0";
  std::uint16_t port = 8443;
  unsigned threads = 2;

  // Both required to serve: there is no plaintext listener. `lugh-node init` needs neither.
  std::string tls_certificate;
  std::string tls_key;

  // Where the node keeps what is its own: the keyring now, the store from P3. systemd makes
  // it, 0700 and owned by lugh; the unit names it.
  std::string state_directory = "/var/lib/lugh";

  // A list of passwords no one may set, one per line. Empty: none.
  std::string breached_passwords;

  // The policy that permits client_secret_basic for an application. Off: applications
  // authenticate with private_key_jwt or tls_client_auth.
  bool allow_client_secrets = false;

  // The dashboard's built files (P7), read once at start and served for every path the routers do
  // not own. Empty: no dashboard, and such a path is a 404.
  std::string static_directory;

  // The issuer: `iss` in every token, and the base of every URL in the metadata. An https
  // URL without a query, fragment or trailing '/'. Empty: no metadata is served.
  std::string issuer;

  // The mTLS listener (RFC 8705), on the same address: it asks every connection for a client
  // certificate, which the main listener never does, so a browser is never shown a
  // certificate picker. Zero: none, and tls_client_auth and certificate-bound tokens are
  // unavailable.
  std::uint16_t mtls_port = 0;

  // The CA a client certificate must chain to for its subject to name a client. Empty: only a
  // certificate's thumbprint names one.
  std::string tls_client_ca;
  // The roots an application's certificate is checked against when Lugh posts to it; the
  // system's when empty. Never a way to stop checking.
  std::string outbound_ca;

  // LDAP (TODO/2026-11-04-ldap.md): LDAPS, and a plaintext port that does nothing but StartTLS and
  // the rootDSE. Zero: that listener is not there. Either needs base_dn.
  std::uint16_t ldap_port = 0;
  std::uint16_t ldap_starttls_port = 0;
  std::string ldap_base_dn;
  std::size_t ldap_most_pending = 8;
  std::uint32_t ldap_idle_seconds = 600;
  // Whether a bind with no name and no password succeeds, staying anonymous (the maintainer, 2026-11-06).
  bool ldap_anonymous_bind = false;
  // POSIX numbers (TODO/2026-11-04-ldap.md): none until a range is set, and then both ranges and the
  // primary group are needed. Ranges are "first-last".
  std::optional<std::pair<std::uint32_t, std::uint32_t>> ldap_uid_range;
  std::optional<std::pair<std::uint32_t, std::uint32_t>> ldap_gid_range;
  std::string ldap_primary_group;
  std::string ldap_home = "/home/{name}";
  std::string ldap_shell = "/bin/bash";

  // A request from one of these is taken at the last X-Forwarded-For entry not in them;
  // everything else at its socket's address. Empty by default: no proxy is trusted until named.
  std::vector<network::Cidr> trusted_proxies;
};

// Lugh's settings, read by Dannan's settings reader (dannan/config/config.h, the one reader
// for every node binary in the stack) and then checked and typed here: the addresses,
// networks and levels are Lugh's to understand.
class ConfigLoader {
 public:
  static constexpr const char* kInstalledPath = LUGH_INSTALLED_CONFIG;

  // default_path is read when neither --config nor $LUGH_CONFIG names a file, and only if
  // it exists; empty reads nothing.
  ConfigLoader(std::shared_ptr<const system::Environment> environment, std::string default_path);

  // The defaults, then the file, then secrets.yaml beside it, then the environment, then
  // the command line, each overriding the one before. A value that cannot be used is an
  // error, never a silent default, in the same words from any layer.
  Result<Config> load(const cli::Options& options);

  // Keys present in a file that nothing reads: a misspelling, most likely. For the log.
  const std::vector<std::string>& warnings() const { return _warnings; }

  // Every setting, as the reader takes it.
  static std::vector<dannan::config::Setting> settings();
  // The flags, settings and variables, for the usage text.
  static std::string describe();

 private:
  std::shared_ptr<const system::Environment> _environment;
  std::string _default_path;
  std::vector<std::string> _warnings;
};

}  // namespace lugh
