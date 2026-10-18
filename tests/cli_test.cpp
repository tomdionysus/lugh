#include "cli.h"

#include <gtest/gtest.h>

#include <string>
#include <vector>

using lugh::cli::Options;

namespace {

Options parse(std::vector<std::string> arguments) {
  arguments.insert(arguments.begin(), "lugh");
  std::vector<char*> argv;
  for (auto& argument : arguments) argv.push_back(argument.data());
  return lugh::cli::parse(static_cast<int>(argv.size()), argv.data());
}

}  // namespace

TEST(Cli, NothingIsFine) { EXPECT_TRUE(parse({}).ok); }

TEST(Cli, TakesBothForms) {
  const auto options = parse({"--config", "/a.yaml", "--port=8099", "-c", "/b.yaml"});
  ASSERT_TRUE(options.ok);
  EXPECT_EQ(options.config, "/b.yaml");
  EXPECT_EQ(options.port, "8099");
}

TEST(Cli, EverySetting) {
  const auto options = parse({"--address", "127.0.0.1", "--tls-certificate", "c.pem", "--tls-key", "k.pem", "--log-level", "debug", "--log-format", "json"});
  ASSERT_TRUE(options.ok);
  EXPECT_EQ(options.address, "127.0.0.1");
  EXPECT_EQ(options.tls_certificate, "c.pem");
  EXPECT_EQ(options.tls_key, "k.pem");
  EXPECT_EQ(options.log_level, "debug");
  EXPECT_EQ(options.log_format, "json");
}

TEST(Cli, VersionAndHelp) {
  EXPECT_TRUE(parse({"-v"}).version);
  EXPECT_TRUE(parse({"--help"}).help);
}

TEST(Cli, UnknownIsAnError) {
  const auto options = parse({"--prot", "80"});
  EXPECT_FALSE(options.ok);
  EXPECT_EQ(options.error, "unknown option: --prot");
}

TEST(Cli, AMissingValueIsAnError) {
  EXPECT_FALSE(parse({"--port"}).ok);
  EXPECT_FALSE(parse({"--port="}).ok);
}

TEST(Cli, UsageNamesEverySetting) {
  const auto text = lugh::cli::usage();
  for (const auto* flag : {"--config", "--address", "--port", "--tls-certificate", "--tls-key", "--log-level", "--log-format"}) {
    EXPECT_NE(text.find(flag), std::string::npos) << flag;
  }
}
