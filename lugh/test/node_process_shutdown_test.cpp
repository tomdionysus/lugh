//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <csignal>

#include "lugh/test/fixtures/node_process.h"

// The service stops on SIGTERM and SIGINT, promptly and cleanly: a shutdown that hangs
// would stall every deploy for systemd's stop timeout. A keyring is made with init, the
// master key put where systemd would load the credential, and the real binary started on a
// configuration file of its own; once /health answers over TLS it is sent the signal, and
// must exit with status 0 within 5 seconds, saying so in its log. Adapted from
// blackraven-admin.

namespace {

using namespace node_process;

void stops_on(int number, const std::string& name) {
  Workspace workspace;
  const auto state = workspace.path("state");
  const auto config = workspace.path("config.yaml");
  write_file(config, "log: { level: info }\nhttps: { tls: { certificate: \"" + workspace.certificate.string() + "\", key: \"" + workspace.key.string() +
                         "\" } }\ncluster: { state: \"" + state.string() + "\" }\n");

  const auto credentials = workspace.path("credentials");
  std::filesystem::create_directories(credentials);
  const auto made = run(workspace, {"init", "--config", config.string()});
  ASSERT_EQ(made.status, 0) << made.err;
  write_file(credentials / kCredential, made.out);

  const auto port = dannan::test::free_port();
  const auto log = workspace.path("serve.log");
  dannan::test::ChildProcess node({kBinary, "--config", config.string(), "--https-listen-address", "127.0.0.1", "--https-listen-port", std::to_string(port)},
                                  log, {.environment = environment(credentials), .input = std::nullopt, .terminal = false});
  ASSERT_TRUE(wait_until_up(node, port, std::chrono::seconds(10))) << read_file(log);

  const auto sent = Clock::now();
  node.signal(number);
  const auto status = node.wait(sent + std::chrono::seconds(5));
  const auto took = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - sent);
  const auto text = read_file(log);

  ASSERT_TRUE(status.has_value()) << name << ": still running 5 s after the signal\n" << text;
  EXPECT_EQ(*status, 0) << text;
  // The signal is Dannan's helper's to take; Lugh says it is stopping when its drain begins.
  EXPECT_NE(text.find("Stopping"), std::string::npos) << text;
  EXPECT_NE(text.find("Stopped"), std::string::npos) << text;
  ::testing::Test::RecordProperty("stopped_ms", static_cast<int>(took.count()));
}

}  // namespace

TEST(NodeProcess, StopsOnSigterm) { stops_on(SIGTERM, "SIGTERM"); }

TEST(NodeProcess, StopsOnSigint) { stops_on(SIGINT, "SIGINT"); }
