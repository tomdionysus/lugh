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

#include "lugh/ldap/dn.h"
#include "lugh/oauth/metadata_routes.h"

namespace lugh {

namespace {

using dannan::config::ConfigError;
using Kind = dannan::config::Setting::Kind;

constexpr const char* kLevels = "all, debug, info, warn or error";
constexpr const char* kFormats = "text or json";

// Dannan's spellings, so every node in the stack takes the same ones.
template <typename T, typename Parse>
std::optional<T> parsed(const dannan::config::Settings& settings, const std::string& key, const std::string& what, Parse parse) {
  const auto text = settings.text(key);
  if (!text) return std::nullopt;
  try {
    return parse(*text);
  } catch (const std::invalid_argument&) {
    throw settings.refuse(key, what);
  }
}

}  // namespace

std::vector<dannan::config::Setting> ConfigLoader::settings() {
  return {
      {"log.level", Kind::value, "--log-level", "LUGH_LOG_LEVEL", kLevels},
      {"log.format", Kind::value, "--log-format", "LUGH_LOG_FORMAT", kFormats},
      {"server.address", Kind::value, "--address", "LUGH_ADDRESS", "an IP address"},
      {"server.port", Kind::value, "--port", "LUGH_PORT", "a port, 0 to 65535"},
      {"server.threads", Kind::value, "", "", "a number of threads, 1 to 64"},
      {"tls.certificate", Kind::value, "--tls-certificate", "LUGH_TLS_CERTIFICATE", "a path"},
      {"tls.key", Kind::value, "--tls-key", "LUGH_TLS_KEY", "a path"},
      {"proxy.trusted_networks", Kind::list, "", "", "networks, as 10.0.0.0/8"},
      {"state.directory", Kind::value, "--state-directory", "LUGH_STATE_DIRECTORY", "a path"},
      {"authn.breached_passwords", Kind::value, "", "", "a path"},
      {"oauth.allow_client_secrets", Kind::toggle, "", "", "true or false"},
      {"oauth.issuer", Kind::value, "--issuer", "LUGH_ISSUER", "an https URL without a query, fragment or trailing '/'"},
      {"oauth.mtls_port", Kind::value, "--mtls-port", "LUGH_MTLS_PORT", "a port, 1 to 65535, or 0 for none"},
      {"tls.client_ca", Kind::value, "", "", "a path"},
      {"oauth.outbound_ca", Kind::value, "", "", "a path"},
      {"ldap.port", Kind::value, "", "", "a port, 1 to 65535, or 0 for none"},
      {"ldap.starttls_port", Kind::value, "", "", "a port, 1 to 65535, or 0 for none"},
      {"ldap.base_dn", Kind::value, "", "", "a distinguished name"},
      {"ldap.most_pending", Kind::value, "", "", "a number of operations, 1 to 256"},
      {"ldap.idle", Kind::value, "", "", "a number of seconds, 1 to 86400"},
      {"ldap.posix.uid_range", Kind::value, "", "", "two numbers, first-last, from 1"},
      {"ldap.posix.gid_range", Kind::value, "", "", "two numbers, first-last, from 1"},
      {"ldap.posix.primary_group", Kind::value, "", "", "a group's name"},
      {"ldap.posix.home", Kind::value, "", "", "a path, with {name} for the user's"},
      {"ldap.posix.shell", Kind::value, "", "", "a path"},
  };
}

std::string ConfigLoader::describe() {
  dannan::config::Reader reader;
  reader.settings = settings();
  reader.config_variable = "LUGH_CONFIG";
  return reader.describe();
}

ConfigLoader::ConfigLoader(std::shared_ptr<const system::Environment> environment, std::string default_path)
    : _environment(std::move(environment)), _default_path(std::move(default_path)) {}

Result<Config> ConfigLoader::load(const cli::Options& options) {
  _warnings.clear();

  dannan::config::Reader reader;
  reader.settings = settings();
  reader.config_variable = "LUGH_CONFIG";
  reader.default_path = _default_path;
  reader.environment = _environment.get();

  try {
    const auto read = reader.read(options.arguments);
    _warnings = read.warnings;

    Config config;
    config.path = read.path;

    if (read.positional.size() > 1) return Result<Config>::failure("unexpected argument: " + read.positional[1]);
    if (!read.positional.empty()) {
      if (read.positional[0] != "init") return Result<Config>::failure("unknown command: " + read.positional[0]);
      config.command = cli::Command::init;
    }
    if (options.passphrase && config.command != cli::Command::init) return Result<Config>::failure("--passphrase is for init");

    if (const auto level =
            parsed<dannan::status::LogLevel>(read, "log.level", kLevels, [](const std::string& text) { return dannan::status::parse_log_level(text); }))
      config.log_level = *level;
    if (const auto format =
            parsed<dannan::status::LogFormat>(read, "log.format", kFormats, [](const std::string& text) { return dannan::status::parse_log_format(text); }))
      config.log_format = *format;

    if (const auto address = read.text("server.address")) {
      boost::system::error_code ec;
      boost::asio::ip::make_address(*address, ec);
      if (ec) throw read.refuse("server.address", "an IP address");
      config.address = *address;
    }
    if (const auto port = read.number("server.port", 0, 65535)) config.port = static_cast<std::uint16_t>(*port);
    if (const auto threads = read.number("server.threads", 1, 64)) config.threads = static_cast<unsigned>(*threads);
    if (const auto certificate = read.path_of("tls.certificate")) config.tls_certificate = *certificate;
    if (const auto key = read.path_of("tls.key")) config.tls_key = *key;
    if (const auto directory = read.path_of("state.directory")) config.state_directory = *directory;
    if (const auto breached = read.text("authn.breached_passwords")) config.breached_passwords = *breached;
    if (const auto secrets = read.toggle("oauth.allow_client_secrets")) config.allow_client_secrets = *secrets;
    if (const auto issuer = read.text("oauth.issuer")) {
      if (!oauth::MetadataRoutes::issuer_ok(*issuer)) throw read.refuse("oauth.issuer", "an https URL without a query, fragment or trailing '/'");
      config.issuer = *issuer;
    }

    if (const auto port = read.number("oauth.mtls_port", 0, 65535)) config.mtls_port = static_cast<std::uint16_t>(*port);
    if (const auto ca = read.path_of("tls.client_ca")) config.tls_client_ca = *ca;
    if (const auto ca = read.path_of("oauth.outbound_ca")) config.outbound_ca = *ca;
    if (const auto port = read.number("ldap.port", 0, 65535)) config.ldap_port = static_cast<std::uint16_t>(*port);
    if (const auto port = read.number("ldap.starttls_port", 0, 65535)) config.ldap_starttls_port = static_cast<std::uint16_t>(*port);
    if (const auto base = read.text("ldap.base_dn")) {
      const auto parsed = ldap::parse_dn(*base);
      if (!parsed || parsed->empty()) throw read.refuse("ldap.base_dn", "a distinguished name");
      config.ldap_base_dn = *base;
    }
    if (const auto pending = read.number("ldap.most_pending", 1, 256)) config.ldap_most_pending = static_cast<std::size_t>(*pending);
    if (const auto idle = read.number("ldap.idle", 1, 86400)) config.ldap_idle_seconds = static_cast<std::uint32_t>(*idle);
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
      const auto cidr = network::Cidr::parse(text);
      if (!cidr) return Result<Config>::failure(read.find("proxy.trusted_networks")->source + ": proxy.trusted_networks: not a network: " + text);
      config.trusted_proxies.push_back(*cidr);
    }

    // No layer may leave these out when serving: there is nothing to fall back to.
    if (config.command == cli::Command::serve && (config.tls_certificate.empty() || config.tls_key.empty())) {
      return Result<Config>::failure("tls.certificate and tls.key must both be set: Lugh has no plaintext listener");
    }
    return Result<Config>::success(std::move(config));
  } catch (const ConfigError& e) {
    return Result<Config>::failure(e.what());
  }
}

}  // namespace lugh
