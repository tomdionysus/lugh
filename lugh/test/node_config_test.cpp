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
  Arguments out{"--https-tls-certificate", "/etc/lugh/cert.pem", "--https-tls-key", "/etc/lugh/key.pem"};
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

const std::string kTls = "https: { tls: { certificate: /c.pem, key: /k.pem } }\n";

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
  EXPECT_FALSE(Loader().load({"--https-tls-certificate", "/c.pem"}).ok);
}

TEST(Config, InitNeedsNoTlsPair) {
  const auto result = Loader().load({"init"});
  ASSERT_TRUE(result.ok) << result.error;
  EXPECT_EQ(result.value.command, Command::init);
}

TEST(Config, TheCommandWord) {
  const auto after = Loader().load({"--cluster-state=/var/lib/lugh", "init"}, true);
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
  EXPECT_FALSE(Loader().load(with_tls({"--https-listen-port"})).ok);
}

TEST(Config, ReadsEverySettingFromTheFile) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml",
                              "log: { level: debug, format: json }\n"
                              "https: { listen: { address: 127.0.0.1, port: 8099 }, tls: { certificate: /srv/cert.pem, key: /srv/key.pem } }\n"
                              "node: { io_threads: 4 }\n"
                              "proxy: { trusted_networks: [10.255.0.0/16] }\n"
                              "cluster: { state: /srv/lugh }\n"
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
  const auto path = dir.write(
      "config.yaml", "https: { listen: { port: 8099 }, tls: { certificate: /c.pem, key: /k.pem } }\nlog: { level: warn }\ncluster: { state: /file/lugh }\n");
  dir.write("secrets.yaml", "https: { listen: { port: 8100 } }\n");

  EXPECT_EQ(Loader().load({"--config", path.string()}).value.port, 8100);

  const auto from_environment =
      Loader({{"LUGH_HTTPS_LISTEN_PORT", "8101"}, {"LUGH_LOG_LEVEL", "error"}, {"LUGH_HTTPS_TLS_KEY", "/env/key.pem"}, {"LUGH_CLUSTER_STATE", "/env/lugh"}})
          .load({"--config", path.string()})
          .value;
  EXPECT_EQ(from_environment.port, 8101);
  EXPECT_EQ(from_environment.log_level, dannan::status::LogLevel::error);
  EXPECT_EQ(from_environment.tls_key, "/env/key.pem");
  EXPECT_EQ(from_environment.tls_certificate, "/c.pem");
  EXPECT_EQ(from_environment.state_directory, "/env/lugh");

  const auto from_cli = Loader({{"LUGH_HTTPS_LISTEN_PORT", "8101"}, {"LUGH_CLUSTER_STATE", "/env/lugh"}})
                            .load(with_config(path.string(), {"--https-listen-port", "443", "--cluster-state", "/cli/lugh"}))
                            .value;
  EXPECT_EQ(from_cli.port, 443);
  EXPECT_EQ(from_cli.tls_certificate, "/etc/lugh/cert.pem");
  EXPECT_EQ(from_cli.state_directory, "/cli/lugh");
}

TEST(Config, TheEnvironmentCanNameTheFile) {
  TempDirectory dir;
  const auto path = dir.write("elsewhere.yaml", "https: { listen: { port: 8102 } }\n");
  EXPECT_EQ(Loader({{"LUGH_CONFIG", path.string()}}).load(with_tls()).value.port, 8102);
}

TEST(Config, TheDefaultPathIsReadOnlyIfItExists) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "https: { listen: { port: 8103 } }\n");
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
  const auto path = dir.write("config.yaml", "https: { listen: { prot: 80 } }\n");
  Loader load;
  const auto result = load.load(with_config(path.string()));
  ASSERT_TRUE(result.ok) << result.error;
  EXPECT_EQ(result.value.port, 8443);
  ASSERT_EQ(load.warnings().size(), 1u);
  EXPECT_NE(load.warnings()[0].find("https.listen.prot"), std::string::npos);
}

TEST(Config, BadValuesAreRefusedSayingWhereTheyCameFrom) {
  TempDirectory dir;
  const auto path = dir.write("config.yaml", "log: { level: loud }\n");
  const auto file_result = Loader().load(with_config(path.string()));
  EXPECT_FALSE(file_result.ok);
  EXPECT_NE(file_result.error.find("log.level"), std::string::npos);
  EXPECT_NE(file_result.error.find(path.string()), std::string::npos);

  const auto env_result = Loader({{"LUGH_HTTPS_LISTEN_PORT", "eighty"}}).load(with_tls());
  EXPECT_FALSE(env_result.ok);
  EXPECT_NE(env_result.error.find("LUGH_HTTPS_LISTEN_PORT"), std::string::npos);

  const auto cli_result = Loader().load(with_tls({"--https-listen-address", "id.blackraven.co.nz"}));
  EXPECT_FALSE(cli_result.ok);
  EXPECT_NE(cli_result.error.find("--https-listen-address"), std::string::npos);
  EXPECT_NE(cli_result.error.find("an IP address"), std::string::npos);

  const auto format = Loader().load(with_tls({"--log-format", "xml"}));
  EXPECT_FALSE(format.ok);
  EXPECT_NE(format.error.find("text or json"), std::string::npos);
}

TEST(Config, RefusesValuesOutOfRange) {
  for (const auto* port : {"65536", "-1", "80x", "99999999999"}) EXPECT_FALSE(Loader().load(with_tls({"--https-listen-port", port})).ok) << port;

  TempDirectory dir;
  EXPECT_FALSE(Loader().load(with_config(dir.write("c.yaml", "node: { io_threads: 0 }\n").string())).ok);
  EXPECT_FALSE(Loader().load(with_config(dir.write("d.yaml", "node: { io_threads: 65 }\n").string())).ok);
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
  EXPECT_FALSE(Loader().load(with_config(dir.write("config.yaml", "https: [unclosed\n").string())).ok);
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
  EXPECT_EQ(Loader({{"LUGH_OAUTH_ISSUER", "https://lugh.example.org"}}).load(with_tls()).value.issuer, "https://lugh.example.org");

  for (const auto* bad : {"http://id.example.com", "https://id.example.com/", "https://id.example.com?x"}) {
    const auto refused = Loader().load(with_tls({"--oauth-issuer", bad}));
    EXPECT_FALSE(refused.ok) << bad;
    EXPECT_NE(refused.error.find("--oauth-issuer"), std::string::npos) << refused.error;
  }
}

TEST(Config, TheLdapListeners) {
  const auto none = Loader().load(with_tls()).value;
  EXPECT_EQ(none.ldap_port, 0);
  EXPECT_EQ(none.ldap_starttls_port, 0);
  EXPECT_EQ(none.ldap_most_pending, 8u);
  EXPECT_EQ(none.ldap_idle_seconds, 600u);
  EXPECT_FALSE(none.ldap_anonymous_bind) << "off unless asked for";

  TempDirectory dir;
  const auto path = dir.write(
      "config.yaml", "ldap: { listen: { port: 636 }, starttls: { listen: { port: 389 } }, base_dn: 'dc=example,dc=com', most_pending: 4, idle: 60 }\n");
  const auto config = Loader().load(with_config(path.string())).value;
  EXPECT_EQ(config.ldap_port, 636);
  EXPECT_EQ(config.ldap_starttls_port, 389);
  EXPECT_EQ(config.ldap_base_dn, "dc=example,dc=com");
  EXPECT_EQ(config.ldap_most_pending, 4u);
  EXPECT_EQ(config.ldap_idle_seconds, 60u);
  EXPECT_TRUE(Loader().load(with_config(dir.write("on.yaml", "ldap: { anonymous_bind: true }\n").string())).value.ldap_anonymous_bind);
  EXPECT_FALSE(Loader().load(with_config(dir.write("off.yaml", "ldap: { anonymous_bind: false }\n").string())).value.ldap_anonymous_bind);
  EXPECT_FALSE(Loader().load(with_config(dir.write("bad.yaml", "ldap: { anonymous_bind: perhaps }\n").string())).ok);

  // A listener needs to know the top of the tree, and is told it properly.
  EXPECT_FALSE(Loader().load(with_config(dir.write("a.yaml", "ldap: { listen: { port: 636 } }\n").string())).ok);
  EXPECT_FALSE(Loader().load(with_config(dir.write("b.yaml", "ldap: { starttls: { listen: { port: 389 } } }\n").string())).ok);
  EXPECT_FALSE(Loader().load(with_config(dir.write("c.yaml", "ldap: { listen: { port: 636 }, base_dn: 'not a dn' }\n").string())).ok);
  EXPECT_FALSE(Loader().load(with_config(dir.write("d.yaml", "ldap: { listen: { port: 70000 }, base_dn: 'dc=x' }\n").string())).ok);
  EXPECT_FALSE(Loader().load(with_config(dir.write("e.yaml", "ldap: { listen: { port: 636 }, base_dn: 'dc=x', most_pending: 0 }\n").string())).ok);
}

TEST(Config, ThePosixNumbers) {
  EXPECT_FALSE(Loader().load(with_tls()).value.ldap_uid_range);
  TempDirectory dir;
  const auto good =
      dir.write("g.yaml", "ldap: { posix: { uid_range: 10000-19999, gid_range: 20000-29999, primary_group: staff, home: '/srv/{name}', shell: /bin/zsh } }\n");
  const auto config = Loader().load(with_config(good.string())).value;
  ASSERT_TRUE(config.ldap_uid_range);
  EXPECT_EQ(config.ldap_uid_range->first, 10000u);
  EXPECT_EQ(config.ldap_uid_range->second, 19999u);
  EXPECT_EQ(config.ldap_gid_range->first, 20000u);
  EXPECT_EQ(config.ldap_primary_group, "staff");
  EXPECT_EQ(config.ldap_home, "/srv/{name}");
  EXPECT_EQ(config.ldap_shell, "/bin/zsh");

  const auto refused = [&](const std::string& name, const std::string& text) { return !Loader().load(with_config(dir.write(name, text).string())).ok; };
  EXPECT_TRUE(refused("a.yaml", "ldap: { posix: { uid_range: 1-2 } }\n")) << "all three go together";
  EXPECT_TRUE(refused("b.yaml", "ldap: { posix: { primary_group: staff } }\n"));
  EXPECT_TRUE(refused("c.yaml", "ldap: { posix: { uid_range: 5-1, gid_range: 1-5, primary_group: staff } }\n")) << "backwards";
  EXPECT_TRUE(refused("d.yaml", "ldap: { posix: { uid_range: 0-5, gid_range: 1-5, primary_group: staff } }\n")) << "root's is not given out";
  EXPECT_TRUE(refused("e.yaml", "ldap: { posix: { uid_range: many, gid_range: 1-5, primary_group: staff } }\n"));
  EXPECT_TRUE(refused("f.yaml", "ldap: { posix: { uid_range: 1-99999999999, gid_range: 1-5, primary_group: staff } }\n"));
}

TEST(Config, TheMtlsListener) {
  EXPECT_EQ(Loader().load(with_tls()).value.mtls_port, 0);
  TempDirectory dir;
  const auto path =
      dir.write("config.yaml", "oauth: { outbound_ca: /etc/lugh/outbound.pem }\nmtls: { listen: { port: 8444 }, tls: { ca: /etc/lugh/clients.pem } }\n");
  const auto config = Loader().load(with_config(path.string())).value;
  EXPECT_EQ(config.mtls_port, 8444);
  EXPECT_EQ(config.tls_client_ca, "/etc/lugh/clients.pem");
  EXPECT_EQ(config.outbound_ca, "/etc/lugh/outbound.pem");
  EXPECT_FALSE(Loader().load(with_tls({"--mtls-listen-port", "70000"})).ok);
  // The HTTPS listener never asks for a client certificate, so a CA for it is refused, not ignored.
  const auto https_ca = Loader().load(with_config(dir.write("ca.yaml", "https: { tls: { ca: /etc/lugh/clients.pem } }\n").string()));
  EXPECT_FALSE(https_ca.ok);
  EXPECT_NE(https_ca.error.find("mtls.tls.ca"), std::string::npos) << https_ca.error;
}
