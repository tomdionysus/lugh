//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/node/config.h"

#include <boost/asio/ip/address.hpp>
#include <stdexcept>
#include <utility>

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
