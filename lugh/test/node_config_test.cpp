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
using lugh::Result;
using lugh::cli::Command;
using lugh::cli::Options;
using Arguments = std::vector<std::string>;

namespace {

// The settings are read by Dannan's reader, whose own layering is tested in Dannan; these
// say what Lugh's settings are and how Lugh checks them.
class Loader {
 public:
  explicit Loader(std::map<std::string, std::string> environment = {}, std::string default_path = "")
      : _loader(std::make_shared<MapEnvironment>(std::move(environment)), std::move(default_path)) {}

  Result<Config> load(Arguments arguments, bool passphrase = false) {
    Options options;
    options.arguments = std::move(arguments);
    options.passphrase = passphrase;
    return _loader.load(options);
  }

  const std::vector<std::string>& warnings() const { return _loader.warnings(); }

 private:
  ConfigLoader _loader;
};

// Every serve needs the TLS pair, so the tests about other settings give it on the command
// line and are about what they are about.
Arguments with_tls(Arguments more = {}) {
  Arguments out{"--tls-certificate", "/etc/lugh/cert.pem", "--tls-key", "/etc/lugh/key.pem"};
  out.insert(out.end(), more.begin(), more.end());
  return out;
}

Arguments with_config(const std::string& path, Arguments more = {}) {
  more.insert(more.begin(), {"--config", path});
  return with_tls(more);
}

std::vector<std::string> networks(const Config& config) {
  std::vector<std::string> out;
  for (const auto& network : config.trusted_proxies) out.push_back(network.to_string());
  return out;
}

const std::string kTls = "tls: { certificate: /c.pem, key: /k.pem }\n";

}  // namespace

TEST(Config, DefaultsWithNoFileAnywhere) {
  const auto result = Loader().load(with_tls());
  ASSERT_TRUE(result.ok) << result.error;

  const auto& config = result.value;
  EXPECT_EQ(config.command, Command::serve);
  EXPECT_TRUE(config.path.empty());
  EXPECT_EQ(config.address, "0.0.0.0");
  EXPECT_EQ(config.port, 8443);
  EXPECT_EQ(config.threads, 2u);
  EXPECT_EQ(config.log_level, dannan::status::LogLevel::info);
  EXPECT_EQ(config.log_format, dannan::status::LogFormat::text);
  EXPECT_EQ(config.state_directory, "/var/lib/lugh");
  EXPECT_EQ(config.breached_passwords, "");
  EXPECT_TRUE(config.trusted_proxies.empty());
}

TEST(Config, TheTlsPairIsRequiredToServe) {
  const auto result = Loader().load({});
  EXPECT_FALSE(result.ok);
  EXPECT_NE(result.error.find("tls.certificate"), std::string::npos);
  EXPECT_NE(result.error.find("no plaintext"), std::string::npos);
  EXPECT_FALSE(Loader().load({"--tls-certificate", "/c.pem"}).ok);
}

TEST(Config, InitNeedsNoTlsPair) {
  const auto result = Loader().load({"init"});
  ASSERT_TRUE(result.ok) << result.error;
  EXPECT_EQ(result.value.command, Command::init);
}

TEST(Config, TheCommandWord) {
  const auto after = Loader().load({"--state-directory=/var/lib/lugh", "init"}, true);
  ASSERT_TRUE(after.ok) << after.error;
  EXPECT_EQ(after.value.command, Command::init);

  const auto unknown = Loader().load(with_tls({"serve"}));
  EXPECT_FALSE(unknown.ok);
  EXPECT_EQ(unknown.error, "unknown command: serve");

  const auto stray = Loader().load({"init", "now"});
  EXPECT_FALSE(stray.ok);
  EXPECT_EQ(stray.error, "unexpected argument: now");
  EXPECT_FALSE(Loader().load({"init", "init"}).ok);
}

TEST(Config, PassphraseIsForInitOnly) {
  const auto result = Loader().load(with_tls(), true);
  EXPECT_FALSE(result.ok);
  EXPECT_EQ(result.error, "--passphrase is for init");
}

TEST(Config, UnknownFlagsAndMissingValuesAreErrors) {
  const auto unknown = Loader().load(with_tls({"--prot", "80"}));
  EXPECT_FALSE(unknown.ok);
  EXPECT_NE(unknown.error.find("--prot"), std::string::npos);
  EXPECT_FALSE(Loader().load(with_tls({"--port"})).ok);
}

TEST(Config, ReadsEverySettingFromTheFile) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml",
                              "log: { level: debug, format: json }\n"
                              "server: { address: 127.0.0.1, port: 8099, threads: 4 }\n"
                              "tls: { certificate: /srv/cert.pem, key: /srv/key.pem }\n"
                              "proxy: { trusted_networks: [10.255.0.0/16] }\n"
                              "state: { directory: /srv/lugh }\n"
                              "authn: { breached_passwords: /etc/lugh/breached.txt }\n");
  Loader load;
  const auto result = load.load({"--config", path.string()});
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
  EXPECT_EQ(config.state_directory, "/srv/lugh");
  EXPECT_EQ(config.breached_passwords, "/etc/lugh/breached.txt");
  EXPECT_TRUE(load.warnings().empty());
}

TEST(Config, TheLayersInOrder) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "server: { port: 8099 }\nlog: { level: warn }\nstate: { directory: /file/lugh }\n" + kTls);
  dir.write("secrets.yaml", "server: { port: 8100 }\n");

  EXPECT_EQ(Loader().load({"--config", path.string()}).value.port, 8100);

  const auto from_environment =
      Loader({{"LUGH_PORT", "8101"}, {"LUGH_LOG_LEVEL", "error"}, {"LUGH_TLS_KEY", "/env/key.pem"}, {"LUGH_STATE_DIRECTORY", "/env/lugh"}})
          .load({"--config", path.string()})
          .value;
  EXPECT_EQ(from_environment.port, 8101);
  EXPECT_EQ(from_environment.log_level, dannan::status::LogLevel::error);
  EXPECT_EQ(from_environment.tls_key, "/env/key.pem");
  EXPECT_EQ(from_environment.tls_certificate, "/c.pem");
  EXPECT_EQ(from_environment.state_directory, "/env/lugh");

  const auto from_cli = Loader({{"LUGH_PORT", "8101"}, {"LUGH_STATE_DIRECTORY", "/env/lugh"}})
                            .load(with_config(path.string(), {"--port", "443", "--state-directory", "/cli/lugh"}))
                            .value;
  EXPECT_EQ(from_cli.port, 443);
  EXPECT_EQ(from_cli.tls_certificate, "/etc/lugh/cert.pem");
  EXPECT_EQ(from_cli.state_directory, "/cli/lugh");
}

TEST(Config, TheEnvironmentCanNameTheFile) {
  TempDirectory dir;
  const auto path = dir.write("elsewhere.yaml", "server: { port: 8102 }\n");
  EXPECT_EQ(Loader({{"LUGH_CONFIG", path.string()}}).load(with_tls()).value.port, 8102);
}

TEST(Config, TheDefaultPathIsReadOnlyIfItExists) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "server: { port: 8103 }\n");
  EXPECT_EQ(Loader({}, path.string()).load(with_tls()).value.port, 8103);

  const auto absent = Loader({}, (dir.path() / "missing.yaml").string()).load(with_tls());
  ASSERT_TRUE(absent.ok) << absent.error;
  EXPECT_EQ(absent.value.port, 8443);
}

TEST(Config, ANamedFileThatIsMissingIsAnError) {
  const auto result = Loader().load(with_config("/nonexistent/config.yaml"));
  EXPECT_FALSE(result.ok);
  EXPECT_NE(result.error.find("/nonexistent/config.yaml"), std::string::npos);
}

TEST(Config, UnknownKeysAreWarnedNotRead) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "server: { prot: 80 }\n");
  Loader load;
  const auto result = load.load(with_config(path.string()));
  ASSERT_TRUE(result.ok) << result.error;
  EXPECT_EQ(result.value.port, 8443);
  ASSERT_EQ(load.warnings().size(), 1u);
  EXPECT_NE(load.warnings()[0].find("server.prot"), std::string::npos);
}

TEST(Config, BadValuesAreRefusedSayingWhereTheyCameFrom) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "log: { level: loud }\n");
  const auto file_result = Loader().load(with_config(path.string()));
  EXPECT_FALSE(file_result.ok);
  EXPECT_NE(file_result.error.find("log.level"), std::string::npos);
  EXPECT_NE(file_result.error.find(path.string()), std::string::npos);

  const auto env_result = Loader({{"LUGH_PORT", "eighty"}}).load(with_tls());
  EXPECT_FALSE(env_result.ok);
  EXPECT_NE(env_result.error.find("LUGH_PORT"), std::string::npos);

  const auto cli_result = Loader().load(with_tls({"--address", "id.blackraven.co.nz"}));
  EXPECT_FALSE(cli_result.ok);
  EXPECT_NE(cli_result.error.find("--address"), std::string::npos);
  EXPECT_NE(cli_result.error.find("an IP address"), std::string::npos);

  const auto format = Loader().load(with_tls({"--log-format", "xml"}));
  EXPECT_FALSE(format.ok);
  EXPECT_NE(format.error.find("text or json"), std::string::npos);
}

TEST(Config, RefusesValuesOutOfRange) {
  for (const auto* port : {"65536", "-1", "80x", "99999999999"}) EXPECT_FALSE(Loader().load(with_tls({"--port", port})).ok) << port;

  TempDirectory dir;
  EXPECT_FALSE(Loader().load(with_config(dir.write("c.yaml", "server: { threads: 0 }\n").string())).ok);
  EXPECT_FALSE(Loader().load(with_config(dir.write("d.yaml", "server: { threads: 65 }\n").string())).ok);
}

TEST(Config, ABadNetworkIsAnError) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "proxy: { trusted_networks: [10.0.0.1/8] }\n");
  const auto result = Loader().load(with_config(path.string()));
  EXPECT_FALSE(result.ok);
  EXPECT_NE(result.error.find("10.0.0.1/8"), std::string::npos);
  EXPECT_NE(result.error.find(path.string()), std::string::npos);
}

TEST(Config, AnEmptyListOfProxiesTrustsNone) {
  TempDirectory dir;
  const auto result = Loader().load(with_config(dir.write("config.yaml", "proxy: { trusted_networks: [] }\n").string()));
  ASSERT_TRUE(result.ok) << result.error;
  EXPECT_TRUE(result.value.trusted_proxies.empty());
}

TEST(Config, AnEmptyFileIsDefaults) {
  TempDirectory dir;
  const auto result = Loader().load(with_config(dir.write("config.yaml", "").string()));
  ASSERT_TRUE(result.ok) << result.error;
  EXPECT_EQ(result.value.port, 8443);
}

TEST(Config, MalformedYamlIsAnError) {
  TempDirectory dir;
  EXPECT_FALSE(Loader().load(with_config(dir.write("config.yaml", "server: [unclosed\n").string())).ok);
}

TEST(Config, TheIssuerAndClientSecrets) {
  const auto defaults = Loader().load(with_tls()).value;
  EXPECT_TRUE(defaults.issuer.empty());
  EXPECT_FALSE(defaults.allow_client_secrets);

  TempDirectory dir;
  const auto path = dir.write("config.yaml", "oauth: { issuer: \"https://id.example.com\", allow_client_secrets: true }\n");
  const auto from_file = Loader().load(with_config(path.string())).value;
  EXPECT_EQ(from_file.issuer, "https://id.example.com");
  EXPECT_TRUE(from_file.allow_client_secrets);
  EXPECT_EQ(Loader({{"LUGH_ISSUER", "https://lugh.example.org"}}).load(with_tls()).value.issuer, "https://lugh.example.org");

  for (const auto* bad : {"http://id.example.com", "https://id.example.com/", "https://id.example.com?x"}) {
    const auto refused = Loader().load(with_tls({"--issuer", bad}));
    EXPECT_FALSE(refused.ok) << bad;
    EXPECT_NE(refused.error.find("--issuer"), std::string::npos) << refused.error;
  }
}
