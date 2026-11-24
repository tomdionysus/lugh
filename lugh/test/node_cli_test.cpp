//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "lugh/node/cli.h"
#include "lugh/node/config.h"

using lugh::cli::Options;

namespace {

Options parse(std::vector<std::string> arguments) {
  arguments.insert(arguments.begin(), "lugh");
  std::vector<char*> argv;
  for (auto& argument : arguments) argv.push_back(argument.data());
  return lugh::cli::parse(static_cast<int>(argv.size()), argv.data());
}

}  // namespace

// The command line keeps the switches that say what the process does; the command word and
// every setting go, in order, to Dannan's settings reader (node_config_test.cpp).
TEST(Cli, TheSwitches) {
  EXPECT_TRUE(parse({"-v"}).version);
  EXPECT_TRUE(parse({"--version"}).version);
  EXPECT_TRUE(parse({"--help"}).help);
  EXPECT_TRUE(parse({"-h"}).help);
  EXPECT_TRUE(parse({"init", "--passphrase"}).passphrase);
  const auto none = parse({});
  EXPECT_FALSE(none.version || none.help || none.passphrase);
  EXPECT_TRUE(none.arguments.empty());
}

TEST(Cli, EverythingElseGoesToTheReaderInOrder) {
  const auto options = parse({"init", "--config", "/a.yaml", "--passphrase", "--https-listen-port=8099", "--prot", "80"});
  EXPECT_TRUE(options.passphrase);
  EXPECT_EQ(options.arguments, (std::vector<std::string>{"init", "--config", "/a.yaml", "--https-listen-port=8099", "--prot", "80"}));
}

TEST(Cli, UsageNamesEverySetting) {
  const auto text = lugh::cli::usage(lugh::ConfigLoader::describe());
  for (const auto* flag : {"--config", "--https-listen-address", "--https-listen-port", "--https-tls-certificate", "--https-tls-key", "--log-level",
                           "--log-format", "--cluster-state", "--oauth-issuer", "--mtls-listen-port", "--ldap-listen-port", "--passphrase", "init",
                           "systemd-creds", "LUGH_HTTPS_LISTEN_PORT", "https.listen.port"}) {
    EXPECT_NE(text.find(flag), std::string::npos) << flag;
  }
}
