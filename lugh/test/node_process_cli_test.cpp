//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include "lugh/test/fixtures/node_process.h"
#include "lugh/version.h"

// The real binary's command line and its listeners: what it says when asked, and that a node
// which cannot do what it was configured to do stops at once, with why, rather than half run.

using namespace node_process;

namespace {

// A port this test holds, so the node cannot have it.
struct HeldPort {
  boost::asio::io_context io;
  boost::asio::ip::tcp::acceptor acceptor{io, {boost::asio::ip::make_address("127.0.0.1"), 0}};
  std::uint16_t port() const { return acceptor.local_endpoint().port(); }
};

std::vector<std::string> serving(const Workspace& workspace, const Initialised& node, std::uint16_t port) {
  return {"--tls-certificate",
          workspace.certificate.string(),
          "--tls-key",
          workspace.key.string(),
          "--state-directory",
          node.state.string(),
          "--address",
          "127.0.0.1",
          "--port",
          std::to_string(port)};
}

}  // namespace

TEST(NodeProcessCli, HelpAndVersion) {
  Workspace workspace;
  for (const auto* flag : {"--help", "-h"}) {
    const auto help = run(workspace, {flag});
    EXPECT_EQ(help.status, 0) << flag;
    EXPECT_EQ(help.out.rfind("Usage: lugh-node", 0), 0u) << help.out;
    EXPECT_NE(help.out.find("--tls-certificate"), std::string::npos) << "the settings are described";
  }
  const auto version = run(workspace, {"--version"});
  EXPECT_EQ(version.status, 0);
  EXPECT_EQ(version.out, std::string(LUGH_VERSION) + "\n");
}

// A configuration that does not load: the node says which file and why, and stops.
TEST(NodeProcessCli, AConfigurationThatDoesNotLoadStopsTheNode) {
  Workspace workspace;
  const Initialised node(workspace);
  const auto config = workspace.path("broken.yaml");
  write_file(config, "port: [not, a, port\n");
  auto args = serving(workspace, node, dannan::test::free_port());
  args.insert(args.end(), {"--config", config.string()});
  const auto ran = run(workspace, args, {.environment = environment(node.credentials), .input = std::nullopt});
  EXPECT_EQ(ran.status, 1);
  EXPECT_NE(ran.err.find(config.string()), std::string::npos) << ran.err;
}

// Every listener it was given must be its own: a port already in use stops the node.
TEST(NodeProcessCli, APortInUseStopsTheNode) {
  Workspace workspace;
  const Initialised node(workspace);
  HeldPort held;
  const auto https = run(workspace, serving(workspace, node, held.port()), {.environment = environment(node.credentials), .input = std::nullopt});
  EXPECT_EQ(https.status, 1) << https.err;

  auto mtls = serving(workspace, node, dannan::test::free_port());
  const auto config = workspace.path("mtls.yaml");
  write_file(config, "tls: { client_ca: " + workspace.certificate.string() + " }\n");
  mtls.insert(mtls.end(), {"--config", config.string(), "--mtls-port", std::to_string(held.port())});
  const auto mtls_ran = run(workspace, mtls, {.environment = environment(node.credentials), .input = std::nullopt});
  EXPECT_EQ(mtls_ran.status, 1) << mtls_ran.err;

  const auto ldap_config = workspace.path("ldap.yaml");
  write_file(ldap_config, "ldap: { port: " + std::to_string(held.port()) + ", base_dn: \"dc=example,dc=com\" }\n");
  auto ldap = serving(workspace, node, dannan::test::free_port());
  ldap.insert(ldap.end(), {"--config", ldap_config.string()});
  const auto ldap_ran = run(workspace, ldap, {.environment = environment(node.credentials), .input = std::nullopt});
  EXPECT_EQ(ldap_ran.status, 1) << ldap_ran.err;
}

// The mTLS listener (RFC 8705) answers the same routes on its own port, asking each connection
// for a client certificate.
TEST(NodeProcessCli, TheMtlsListenerServesTheSameRoutes) {
  Workspace workspace;
  const Initialised node(workspace);
  const auto config = workspace.path("mtls.yaml");
  write_file(config, "tls: { client_ca: " + workspace.certificate.string() + " }\n");
  const auto mtls_port = dannan::test::free_port();
  Serving serving(workspace, node.state, node.credentials, std::nullopt, {"--config", config.string(), "--mtls-port", std::to_string(mtls_port)});
  ASSERT_TRUE(serving.up()) << serving.log();
  const auto health = request(mtls_port, boost::beast::http::verb::get, "/health");
  ASSERT_TRUE(health.has_value()) << serving.log();
  EXPECT_EQ(health->status, 200u);
  EXPECT_NE(serving.stop().find("Stopped"), std::string::npos);
}
