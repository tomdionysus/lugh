//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/node/config.h"
#include "lugh/test/fixtures/map_environment.h"
#include "lugh/test/fixtures/temp_directory.h"

using lugh::Config;
using lugh::ConfigLoader;
using lugh::cli::Options;

namespace {

ConfigLoader loader(std::map<std::string, std::string> environment = {}, std::string default_path = "") {
  return ConfigLoader(std::make_shared<MapEnvironment>(std::move(environment)), std::move(default_path));
}

// Every load needs the TLS pair, so the tests about other settings give it on the command
// line and are about what they are about.
Options with_tls() {
  Options options;
  options.tls_certificate = "/etc/lugh/cert.pem";
  options.tls_key = "/etc/lugh/key.pem";
  return options;
}

Options with_config(const std::string& path) {
  auto options = with_tls();
  options.config = path;
  return options;
}

std::vector<std::string> networks(const Config& config) {
  std::vector<std::string> out;
  for (const auto& network : config.trusted_proxies) out.push_back(network.to_string());
  return out;
}

const std::string kTls = "tls: { certificate: /c.pem, key: /k.pem }\n";

}  // namespace

TEST(Config, DefaultsWithNoFileAnywhere) {
  auto load = loader();
  const auto result = load.load(with_tls());
  ASSERT_TRUE(result.ok) << result.error;

  const auto& config = result.value;
  EXPECT_TRUE(config.path.empty());
  EXPECT_EQ(config.address, "0.0.0.0");
  EXPECT_EQ(config.port, 8443);
  EXPECT_EQ(config.threads, 2u);
  EXPECT_EQ(config.log_level, dannan::status::LogLevel::info);
  EXPECT_EQ(config.log_format, dannan::status::LogFormat::text);
  EXPECT_TRUE(config.trusted_proxies.empty());
}

TEST(Config, TheTlsPairIsRequired) {
  auto load = loader();
  const auto result = load.load({});
  EXPECT_FALSE(result.ok);
  EXPECT_NE(result.error.find("tls.certificate"), std::string::npos);
  EXPECT_NE(result.error.find("no plaintext"), std::string::npos);

  Options half;
  half.tls_certificate = "/c.pem";
  EXPECT_FALSE(loader().load(half).ok);
}

TEST(Config, ReadsEverySettingFromTheFile) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml",
                              "log: { level: debug, format: json }\n"
                              "server: { address: 127.0.0.1, port: 8099, threads: 4 }\n"
                              "tls: { certificate: /srv/cert.pem, key: /srv/key.pem }\n"
                              "proxy: { trusted_networks: [10.255.0.0/16] }\n");
  Options options;
  options.config = path.string();
  auto load = loader();
  const auto result = load.load(options);
  ASSERT_TRUE(result.ok) << result.error;

  const auto& config = result.value;
  EXPECT_EQ(config.path, path.string());
  EXPECT_EQ(config.log_level, dannan::status::LogLevel::debug);
  EXPECT_EQ(config.log_format, dannan::status::LogFormat::json);
  EXPECT_EQ(config.address, "127.0.0.1");
  EXPECT_EQ(config.port, 8099);
  EXPECT_EQ(config.threads, 4u);
  EXPECT_EQ(config.tls_certificate, "/srv/cert.pem");
  EXPECT_EQ(config.tls_key, "/srv/key.pem");
  EXPECT_EQ(networks(config), (std::vector<std::string>{"10.255.0.0/16"}));
  EXPECT_TRUE(load.warnings().empty());
}

TEST(Config, SecretsBesideTheFileWin) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "server: { port: 8099 }\n");
  dir.write("secrets.yaml", "server: { port: 8100 }\n");

  auto load = loader();
  EXPECT_EQ(load.load(with_config(path.string())).value.port, 8100);
}

TEST(Config, TheEnvironmentWinsOverTheFiles) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "server: { port: 8099 }\nlog: { level: warn }\n" + kTls);

  Options options;
  options.config = path.string();
  auto load = loader({{"LUGH_PORT", "8101"}, {"LUGH_LOG_LEVEL", "error"}, {"LUGH_TLS_KEY", "/env/key.pem"}});
  const auto config = load.load(options).value;
  EXPECT_EQ(config.port, 8101);
  EXPECT_EQ(config.log_level, dannan::status::LogLevel::error);
  EXPECT_EQ(config.tls_key, "/env/key.pem");
  EXPECT_EQ(config.tls_certificate, "/c.pem");
}

TEST(Config, TheCommandLineWinsOverEverything) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "server: { port: 8099 }\n" + kTls);

  auto options = with_config(path.string());
  options.port = "443";

  auto load = loader({{"LUGH_PORT", "8101"}});
  const auto config = load.load(options).value;
  EXPECT_EQ(config.port, 443);
  EXPECT_EQ(config.tls_certificate, "/etc/lugh/cert.pem");
}

TEST(Config, TheEnvironmentCanNameTheFile) {
  TempDirectory dir;
  const auto path = dir.write("elsewhere.yaml", "server: { port: 8102 }\n");

  auto load = loader({{"LUGH_CONFIG", path.string()}});
  EXPECT_EQ(load.load(with_tls()).value.port, 8102);
}

TEST(Config, TheDefaultPathIsReadOnlyIfItExists) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "server: { port: 8103 }\n");

  auto present = loader({}, path.string());
  EXPECT_EQ(present.load(with_tls()).value.port, 8103);

  auto absent = loader({}, (dir.path() / "missing.yaml").string());
  const auto result = absent.load(with_tls());
  ASSERT_TRUE(result.ok);
  EXPECT_EQ(result.value.port, 8443);
}

TEST(Config, ANamedFileThatIsMissingIsAnError) {
  auto load = loader();
  const auto result = load.load(with_config("/nonexistent/config.yaml"));
  EXPECT_FALSE(result.ok);
  EXPECT_NE(result.error.find("/nonexistent/config.yaml"), std::string::npos);
}

TEST(Config, UnknownKeysAreWarnedNotRead) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "server: { prot: 80 }\nstatic: { x: 1 }\n");

  auto load = loader();
  const auto result = load.load(with_config(path.string()));
  ASSERT_TRUE(result.ok);
  EXPECT_EQ(result.value.port, 8443);
  ASSERT_EQ(load.warnings().size(), 2u);
  EXPECT_NE(load.warnings()[0].find("server.prot"), std::string::npos);
  EXPECT_NE(load.warnings()[1].find("static"), std::string::npos);
}

TEST(Config, BadValuesAreRefusedSayingWhereTheyCameFrom) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "log: { level: loud }\n");

  auto from_file = loader();
  const auto file_result = from_file.load(with_config(path.string()));
  EXPECT_FALSE(file_result.ok);
  EXPECT_NE(file_result.error.find("log.level"), std::string::npos);
  EXPECT_NE(file_result.error.find(path.string()), std::string::npos);

  auto from_environment = loader({{"LUGH_PORT", "eighty"}});
  const auto env_result = from_environment.load(with_tls());
  EXPECT_FALSE(env_result.ok);
  EXPECT_NE(env_result.error.find("LUGH_PORT"), std::string::npos);

  auto options = with_tls();
  options.address = "id.blackraven.co.nz";
  auto from_cli = loader();
  const auto cli_result = from_cli.load(options);
  EXPECT_FALSE(cli_result.ok);
  EXPECT_NE(cli_result.error.find("--address"), std::string::npos);
}

TEST(Config, RefusesValuesOutOfRange) {
  for (const auto& port : {"65536", "-1", "80x", "99999999999"}) {
    auto options = with_tls();
    options.port = port;
    auto load = loader();
    EXPECT_FALSE(load.load(options).ok) << port;
  }

  TempDirectory dir;
  auto zero_threads = loader();
  EXPECT_FALSE(zero_threads.load(with_config(dir.write("c.yaml", "server: { threads: 0 }\n").string())).ok);
}

TEST(Config, ABadNetworkIsAnError) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "proxy: { trusted_networks: [10.0.0.1/8] }\n");

  auto load = loader();
  const auto result = load.load(with_config(path.string()));
  EXPECT_FALSE(result.ok);
  EXPECT_NE(result.error.find("10.0.0.1/8"), std::string::npos);
}

TEST(Config, AnEmptyListOfProxiesTrustsNone) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "proxy: { trusted_networks: [] }\n");

  auto load = loader();
  const auto result = load.load(with_config(path.string()));
  ASSERT_TRUE(result.ok) << result.error;
  EXPECT_TRUE(result.value.trusted_proxies.empty());
}

TEST(Config, AnEmptyFileIsDefaults) {
  TempDirectory dir;
  auto load = loader();
  const auto result = load.load(with_config(dir.write("config.yaml", "").string()));
  ASSERT_TRUE(result.ok) << result.error;
  EXPECT_EQ(result.value.port, 8443);
}

TEST(Config, MalformedYamlIsAnError) {
  TempDirectory dir;
  auto load = loader();
  EXPECT_FALSE(load.load(with_config(dir.write("config.yaml", "server: [unclosed\n").string())).ok);
}

TEST(Config, TheStateDirectory) {
  auto defaults = loader();
  EXPECT_EQ(defaults.load(with_tls()).value.state_directory, "/var/lib/lugh");

  TempDirectory dir;
  const auto path = dir.write("config.yaml", "state: { directory: /srv/lugh }\n");
  auto from_file = loader();
  EXPECT_EQ(from_file.load(with_config(path.string())).value.state_directory, "/srv/lugh");

  auto from_environment = loader({{"LUGH_STATE_DIRECTORY", "/env/lugh"}});
  EXPECT_EQ(from_environment.load(with_config(path.string())).value.state_directory, "/env/lugh");

  auto options = with_config(path.string());
  options.state_directory = "/cli/lugh";
  auto from_cli = loader({{"LUGH_STATE_DIRECTORY", "/env/lugh"}});
  EXPECT_EQ(from_cli.load(options).value.state_directory, "/cli/lugh");
}

TEST(Config, TheBreachedPasswordList) {
  auto defaults = loader();
  EXPECT_EQ(defaults.load(with_tls()).value.breached_passwords, "");

  TempDirectory dir;
  const auto path = dir.write("config.yaml", "authn: { breached_passwords: /etc/lugh/breached.txt }\n");
  auto from_file = loader();
  EXPECT_EQ(from_file.load(with_config(path.string())).value.breached_passwords, "/etc/lugh/breached.txt");
}

TEST(Config, InitNeedsNoTlsPair) {
  Options options;
  options.command = lugh::cli::Command::init;
  auto load = loader();
  const auto result = load.load(options);
  EXPECT_TRUE(result.ok) << result.error;
}
