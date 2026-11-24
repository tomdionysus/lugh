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
#include "lugh/core/status.h"
#include "lugh/network/prefix.h"
#include "lugh/version.h"

namespace lugh {

// The HTTPS listener's port when none is given.
inline constexpr std::uint16_t kHttpsPort = 8443;

// Everything Lugh is told at start, beside what the node-program helper reads for the node itself
// (its log, its threads, the cluster). Public fields: it is data, filled once by ConfigLoader and
// read by main. The master key is not here and never will be; it arrives as a systemd credential,
// or is typed.
struct Config {
  // The file read, empty when the defaults alone were used.
  std::string path;

  // init only: a passphrase typed at each start, in place of a systemd credential.
  bool passphrase = false;

  std::string address = "0.0.0.0";
  std::uint16_t port = kHttpsPort;

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
  std::vector<network::Prefix> trusted_proxies;
};

// Lugh's settings. Dannan's node-program helper reads them with its own (cluster.*, log.* and
// node.*: dannan/supervise/node_program.h), in its one order of layers (the defaults, the file,
// secrets.yaml beside it, the environment, the command line), and parses the command line, --help
// and --version. What is Lugh's is which settings there are and how they are checked and typed: the
// addresses, the networks, the issuer, the LDAP tree.
class ConfigLoader {
 public:
  static constexpr const char* kInstalledPath = LUGH_INSTALLED_CONFIG;

  // What the settings are read for: serving needs the TLS pair; init needs neither, and alone
  // takes --passphrase.
  enum class Purpose { serve, init };

  // Lugh's own settings, as the reader takes them, the HTTPS listener's apart.
  static std::vector<dannan::config::Setting> settings();
  // Adds Lugh's settings, the HTTPS listener's with them, to the helper's reader.
  static void add_settings(dannan::config::Reader& reader);

  // Lugh's settings, checked and typed. A value that cannot be used is a failure naming the
  // setting and where it came from, never a silent default.
  static Result<Config> read(const dannan::config::Settings& settings, Purpose purpose);
};

}  // namespace lugh
