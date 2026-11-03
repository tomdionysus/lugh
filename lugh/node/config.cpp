//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/node/config.h"

#include <yaml-cpp/yaml.h>

#include <boost/asio/ip/address.hpp>
#include <cctype>
#include <filesystem>
#include <map>
#include <optional>
#include <set>
#include <utility>

namespace lugh {

namespace {

// Every key a file may hold, by section. Anything else is reported, not read.
const std::map<std::string, std::set<std::string>> kKnownKeys{
    {"log", {"level", "format"}}, {"server", {"address", "port", "threads"}}, {"tls", {"certificate", "key"}}, {"proxy", {"trusted_networks"}},
    {"state", {"directory"}},     {"authn", {"breached_passwords"}},
};

// The environment variable for each setting the environment may override.
const std::vector<std::pair<std::string, std::string>> kEnvironment{
    {"LUGH_ADDRESS", "server.address"}, {"LUGH_PORT", "server.port"},      {"LUGH_TLS_CERTIFICATE", "tls.certificate"}, {"LUGH_TLS_KEY", "tls.key"},
    {"LUGH_LOG_LEVEL", "log.level"},    {"LUGH_LOG_FORMAT", "log.format"}, {"LUGH_STATE_DIRECTORY", "state.directory"},
};

bool all_digits(const std::string& text) {
  if (text.empty()) return false;
  for (const char c : text) {
    if (!std::isdigit(static_cast<unsigned char>(c))) return false;
  }
  return true;
}

std::optional<unsigned long> parse_number(const std::string& text, unsigned long most) {
  if (!all_digits(text) || text.size() > 10) return std::nullopt;
  const auto value = std::stoul(text);
  if (value > most) return std::nullopt;
  return value;
}

std::optional<loggers::LogLevel> parse_level(const std::string& text) {
  if (text == "debug") return loggers::DEBUG;
  if (text == "info") return loggers::INFO;
  if (text == "warn") return loggers::WARN;
  if (text == "error") return loggers::ERROR;
  return std::nullopt;
}

std::optional<loggers::LogFormat> parse_format(const std::string& text) {
  if (text == "text") return loggers::LogFormat::Text;
  if (text == "json") return loggers::LogFormat::Json;
  return std::nullopt;
}

Result<std::vector<network::Cidr>> parse_networks(const std::vector<std::string>& texts, const std::string& source) {
  std::vector<network::Cidr> networks;
  for (const auto& text : texts) {
    const auto cidr = network::Cidr::parse(text);
    if (!cidr) return Result<std::vector<network::Cidr>>::failure(source + ": proxy.trusted_networks: not a network: " + text);
    networks.push_back(*cidr);
  }
  return Result<std::vector<network::Cidr>>::success(std::move(networks));
}

}  // namespace

ConfigLoader::ConfigLoader(std::shared_ptr<system::Environment> environment, std::string default_path)
    : _environment(std::move(environment)), _default_path(std::move(default_path)) {}

Result<Config> ConfigLoader::load(const cli::Options& options) {
  _warnings.clear();

  Config config;

  // Which file: named on the command line or in the environment, it must exist; the
  // installed path is read only if it does.
  std::string path = options.config;
  if (path.empty()) {
    if (const auto named = _environment->get("LUGH_CONFIG"); named && !named->empty()) path = *named;
  }

  if (!path.empty()) {
    if (!std::filesystem::is_regular_file(path)) return Result<Config>::failure("no configuration file at " + path);
  } else if (!_default_path.empty() && std::filesystem::is_regular_file(_default_path)) {
    path = _default_path;
  }

  if (!path.empty()) {
    if (const auto applied = _apply_file(config, path); !applied.ok) return Result<Config>::failure(applied.error);
    config.path = path;

    // Secrets sit beside the configuration, in the same shape, and win over it. Optional.
    const auto secrets = (std::filesystem::path(path).parent_path() / "secrets.yaml").string();
    if (std::filesystem::is_regular_file(secrets)) {
      if (const auto applied = _apply_file(config, secrets); !applied.ok) return Result<Config>::failure(applied.error);
    }
  }

  for (const auto& [variable, key] : kEnvironment) {
    const auto value = _environment->get(variable);
    if (!value) continue;
    if (const auto applied = _apply(config, key, *value, variable); !applied.ok) return Result<Config>::failure(applied.error);
  }

  const std::vector<std::pair<std::string, std::pair<std::string, std::string>>> flags{
      {options.address, {"server.address", "--address"}},
      {options.port, {"server.port", "--port"}},
      {options.tls_certificate, {"tls.certificate", "--tls-certificate"}},
      {options.tls_key, {"tls.key", "--tls-key"}},
      {options.log_level, {"log.level", "--log-level"}},
      {options.log_format, {"log.format", "--log-format"}},
      {options.state_directory, {"state.directory", "--state-directory"}},
  };
  for (const auto& [value, where] : flags) {
    if (value.empty()) continue;
    if (const auto applied = _apply(config, where.first, value, where.second); !applied.ok) return Result<Config>::failure(applied.error);
  }

  // No layer may leave these out when serving: there is nothing to fall back to.
  if (options.command == cli::Command::serve && (config.tls_certificate.empty() || config.tls_key.empty())) {
    return Result<Config>::failure("tls.certificate and tls.key must both be set: Lugh has no plaintext listener");
  }

  return Result<Config>::success(std::move(config));
}

Status ConfigLoader::_apply_file(Config& config, const std::string& path) {
  YAML::Node root;
  try {
    root = YAML::LoadFile(path);
  } catch (const YAML::Exception& e) {
    return Status::failure(path + ": " + e.what());
  }

  // An empty file is a file of defaults.
  if (!root || root.IsNull()) return Status::success();
  if (!root.IsMap()) return Status::failure(path + ": the top level must be a map of sections");

  for (const auto& section : root) {
    const auto name = section.first.as<std::string>();
    const auto known = kKnownKeys.find(name);
    if (known == kKnownKeys.end()) {
      _warnings.push_back(path + ": unknown section " + name + ", not read");
      continue;
    }

    if (section.second.IsNull()) continue;
    if (!section.second.IsMap()) return Status::failure(path + ": " + name + " must be a map");

    for (const auto& entry : section.second) {
      const auto key = entry.first.as<std::string>();
      const auto dotted = name + "." + key;

      if (!known->second.count(key)) {
        _warnings.push_back(path + ": unknown key " + dotted + ", not read");
        continue;
      }

      if (dotted == "proxy.trusted_networks") {
        if (entry.second.IsNull()) {
          config.trusted_proxies.clear();
          continue;
        }
        if (!entry.second.IsSequence()) return Status::failure(path + ": proxy.trusted_networks must be a list");

        std::vector<std::string> texts;
        for (const auto& item : entry.second) {
          if (!item.IsScalar()) return Status::failure(path + ": proxy.trusted_networks holds something that is not a network");
          texts.push_back(item.as<std::string>());
        }

        auto networks = parse_networks(texts, path);
        if (!networks.ok) return Status::failure(networks.error);
        config.trusted_proxies = std::move(networks.value);
        continue;
      }

      if (!entry.second.IsScalar()) return Status::failure(path + ": " + dotted + " must be a single value");
      if (const auto applied = _apply(config, dotted, entry.second.as<std::string>(), path); !applied.ok) return applied;
    }
  }

  return Status::success();
}

// One setting from any layer. The words of a refusal are the same wherever the value
// came from; only the source differs.
Status ConfigLoader::_apply(Config& config, const std::string& key, const std::string& value, const std::string& source) {
  const auto refuse = [&](const std::string& wanted) { return Status::failure(source + ": " + key + " is " + wanted + ", not \"" + value + "\""); };

  if (key == "log.level") {
    const auto level = parse_level(value);
    if (!level) return refuse("debug, info, warn or error");
    config.log_level = *level;
  } else if (key == "log.format") {
    const auto format = parse_format(value);
    if (!format) return refuse("text or json");
    config.log_format = *format;
  } else if (key == "server.address") {
    boost::system::error_code ec;
    boost::asio::ip::make_address(value, ec);
    if (ec) return refuse("an IP address");
    config.address = value;
  } else if (key == "server.port") {
    const auto port = parse_number(value, 65535);
    if (!port) return refuse("a port, 0 to 65535");
    config.port = static_cast<std::uint16_t>(*port);
  } else if (key == "server.threads") {
    const auto threads = parse_number(value, 64);
    if (!threads || *threads == 0) return refuse("a number of threads, 1 to 64");
    config.threads = static_cast<unsigned>(*threads);
  } else if (key == "tls.certificate") {
    if (value.empty()) return refuse("a path");
    config.tls_certificate = value;
  } else if (key == "tls.key") {
    if (value.empty()) return refuse("a path");
    config.tls_key = value;
  } else if (key == "state.directory") {
    if (value.empty()) return refuse("a path");
    config.state_directory = value;
  } else if (key == "authn.breached_passwords") {
    config.breached_passwords = value;
  } else {
    return Status::failure(source + ": " + key + " is not a setting");
  }

  return Status::success();
}

}  // namespace lugh
