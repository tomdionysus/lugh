//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/node/config.h"

#include <boost/asio/ip/address.hpp>
#include <charconv>
#include <stdexcept>
#include <utility>

#include "dannan/supervise/node_program.h"
#include "lugh/ldap/dn.h"
#include "lugh/oauth/metadata_routes.h"

namespace lugh {

namespace {

using dannan::config::ConfigError;
using Kind = dannan::config::Setting::Kind;

}  // namespace

std::vector<dannan::config::Setting> ConfigLoader::settings() {
  return {
      {"passphrase", Kind::toggle, "--passphrase", "", "for init: a passphrase typed at each start, in place of a systemd credential"},
      {"proxy.trusted_networks", Kind::list, "", "", "networks, as 10.0.0.0/8"},
      {"static.directory", Kind::value, "--static-directory", "LUGH_STATIC_DIRECTORY", "a path"},
      {"authn.breached_passwords", Kind::value, "", "", "a path"},
      {"oauth.allow_client_secrets", Kind::toggle, "", "", "true or false"},
      {"oauth.issuer", Kind::value, "--oauth-issuer", "LUGH_OAUTH_ISSUER", "an https URL without a query, fragment or trailing '/'"},
      {"mtls.listen.port", Kind::value, "--mtls-listen-port", "LUGH_MTLS_LISTEN_PORT", "a port, 1 to 65535, or 0 for none"},
      {"mtls.tls.ca", Kind::value, "", "", "a path"},
      {"oauth.outbound_ca", Kind::value, "", "", "a path"},
      {"ldap.listen.port", Kind::value, "--ldap-listen-port", "LUGH_LDAP_LISTEN_PORT", "a port, 1 to 65535, or 0 for none"},
      {"ldap.starttls.listen.port", Kind::value, "--ldap-starttls-listen-port", "LUGH_LDAP_STARTTLS_LISTEN_PORT", "a port, 1 to 65535, or 0 for none"},
      {"ldap.base_dn", Kind::value, "", "", "a distinguished name"},
      {"ldap.most_pending", Kind::value, "", "", "a number of operations, 1 to 256"},
      {"ldap.idle", Kind::value, "", "", "a number of seconds, 1 to 86400"},
      {"ldap.anonymous_bind", Kind::toggle, "", "", "true or false"},
      {"ldap.posix.uid_range", Kind::value, "", "", "two numbers, first-last, from 1"},
      {"ldap.posix.gid_range", Kind::value, "", "", "two numbers, first-last, from 1"},
      {"ldap.posix.primary_group", Kind::value, "", "", "a group's name"},
      {"ldap.posix.home", Kind::value, "", "", "a path, with {name} for the user's"},
      {"ldap.posix.shell", Kind::value, "", "", "a path"},
  };
}

void ConfigLoader::add_settings(dannan::config::Reader& reader) {
  for (auto& setting : settings()) reader.settings.push_back(std::move(setting));
  dannan::supervise::add_listener_settings(reader, "LUGH", "https", kHttpsPort);
}

Result<Config> ConfigLoader::read(const dannan::config::Settings& read, Purpose purpose) {
  try {
    Config config;
    config.path = read.path;
    config.passphrase = read.toggle("passphrase").value_or(false);
    if (config.passphrase && purpose != Purpose::init) return Result<Config>::failure("--passphrase is for init");

    const auto https = dannan::supervise::listener_settings(read, "https", kHttpsPort);
    if (!https.address.empty()) {
      boost::system::error_code ec;
      boost::asio::ip::make_address(https.address, ec);
      if (ec) throw read.refuse("https.listen.address", "an IP address");
      config.address = https.address;
    }
    config.port = https.port;
    if (https.tls) {
      // The HTTPS listener never asks for a client certificate, so a browser is never shown a picker.
      if (!https.tls->client_ca.empty()) throw read.refuse("https.tls.ca", "unset: the mTLS listener's is mtls.tls.ca");
      config.tls_certificate = https.tls->chain.string();
      config.tls_key = https.tls->key.string();
    }
    // The helper's setting, the node's state directory: Lugh's keyring and store are in it too.
    if (const auto directory = read.path_of("cluster.state")) config.state_directory = *directory;
    if (const auto directory = read.path_of("static.directory")) config.static_directory = *directory;
    if (const auto breached = read.text("authn.breached_passwords")) config.breached_passwords = *breached;
    if (const auto secrets = read.toggle("oauth.allow_client_secrets")) config.allow_client_secrets = *secrets;
    if (const auto issuer = read.text("oauth.issuer")) {
      if (!oauth::MetadataRoutes::issuer_ok(*issuer)) throw read.refuse("oauth.issuer", "an https URL without a query, fragment or trailing '/'");
      config.issuer = *issuer;
    }

    if (const auto port = read.number("mtls.listen.port", 0, 65535)) config.mtls_port = static_cast<std::uint16_t>(*port);
    if (const auto ca = read.path_of("mtls.tls.ca")) config.tls_client_ca = *ca;
    if (const auto ca = read.path_of("oauth.outbound_ca")) config.outbound_ca = *ca;
    if (const auto port = read.number("ldap.listen.port", 0, 65535)) config.ldap_port = static_cast<std::uint16_t>(*port);
    if (const auto port = read.number("ldap.starttls.listen.port", 0, 65535)) config.ldap_starttls_port = static_cast<std::uint16_t>(*port);
    if (const auto base = read.text("ldap.base_dn")) {
      const auto parsed = ldap::parse_dn(*base);
      if (!parsed || parsed->empty()) throw read.refuse("ldap.base_dn", "a distinguished name");
      config.ldap_base_dn = *base;
    }
    if (const auto pending = read.number("ldap.most_pending", 1, 256)) config.ldap_most_pending = static_cast<std::size_t>(*pending);
    if (const auto idle = read.number("ldap.idle", 1, 86400)) config.ldap_idle_seconds = static_cast<std::uint32_t>(*idle);
    if (const auto anonymous = read.toggle("ldap.anonymous_bind")) config.ldap_anonymous_bind = *anonymous;
    const auto range_of = [&](const char* key) -> std::optional<std::pair<std::uint32_t, std::uint32_t>> {
      const auto text = read.text(key);
      if (!text) return std::nullopt;
      const auto dash = text->find('-');
      const auto number = [](std::string_view part) -> std::optional<std::uint32_t> {
        std::uint32_t out = 0;
        const auto [at, error] = std::from_chars(part.data(), part.data() + part.size(), out);
        if (error != std::errc() || at != part.data() + part.size() || out == 0) return std::nullopt;
        return out;
      };
      const auto first = dash == std::string::npos ? std::nullopt : number(std::string_view(*text).substr(0, dash));
      const auto last = dash == std::string::npos ? std::nullopt : number(std::string_view(*text).substr(dash + 1));
      if (!first || !last || *first > *last) throw read.refuse(key, "two numbers, first-last, from 1");
      return std::make_pair(*first, *last);
    };
    config.ldap_uid_range = range_of("ldap.posix.uid_range");
    config.ldap_gid_range = range_of("ldap.posix.gid_range");
    if (const auto group = read.text("ldap.posix.primary_group")) config.ldap_primary_group = *group;
    if (const auto home = read.text("ldap.posix.home")) config.ldap_home = *home;
    if (const auto shell = read.text("ldap.posix.shell")) config.ldap_shell = *shell;
    const bool any_posix = config.ldap_uid_range || config.ldap_gid_range || !config.ldap_primary_group.empty();
    if (any_posix && (!config.ldap_uid_range || !config.ldap_gid_range || config.ldap_primary_group.empty())) {
      return Result<Config>::failure("ldap.posix needs uid_range, gid_range and primary_group together");
    }
    if ((config.ldap_port != 0 || config.ldap_starttls_port != 0) && config.ldap_base_dn.empty()) {
      return Result<Config>::failure("ldap.base_dn must be set for an LDAP listener: Lugh does not guess the top of the tree");
    }
    for (const auto& text : read.list("proxy.trusted_networks")) {
      const auto prefix = network::prefix_of(text);
      if (!prefix) return Result<Config>::failure(read.find("proxy.trusted_networks")->source + ": proxy.trusted_networks: not a network: " + text);
      config.trusted_proxies.push_back(*prefix);
    }

    // No layer may leave these out when serving: there is nothing to fall back to.
    if (purpose == Purpose::serve && (config.tls_certificate.empty() || config.tls_key.empty())) {
      return Result<Config>::failure("https.tls.certificate and https.tls.key must both be set: Lugh has no plaintext listener");
    }
    return Result<Config>::success(std::move(config));
  } catch (const ConfigError& e) {
    return Result<Config>::failure(e.what());
  }
}

}  // namespace lugh
