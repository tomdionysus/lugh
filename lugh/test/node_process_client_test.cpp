//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// lugh_client against the real binary, over TLS (P10.6, TODO/2026-11-14-p10-plan.md): a relying
// party's key source reads the node's discovery and JWKS; a service registered for
// private_key_jwt gets tokens by client credentials; the verifier checks them offline; the
// management API answers them; introspection says they are active, and after revocation that they
// are not, while the offline verifier honours them until they expire, as docs/client.md says.

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <optional>

#include "dannan/contract/time_source.h"
#include "dannan/identity/signing.h"
#include "lugh/client/api_client.h"
#include "lugh/client/https.h"
#include "lugh/client/key_source.h"
#include "lugh/client/oauth_client.h"
#include "lugh/client/testing.h"
#include "lugh/client/verifier.h"
#include "lugh/test/fixtures/node_browser.h"
#include "lugh/test/fixtures/node_process.h"

using namespace node_process;
namespace http = boost::beast::http;
namespace client = lugh::client;

namespace {

constexpr lugh::Deadline kCall = std::chrono::seconds(10);

class NodeProcessClient : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_EQ(node.made.status, 0) << node.made.err;
    password = root_password(node.made.err);
    ASSERT_FALSE(password.empty()) << node.made.err;
    // The issuer names the port the node listens on: the client reaches it by that URL.
    const auto port = dannan::test::free_port();
    issuer = "https://localhost:" + std::to_string(port);
    config_path = workspace.path("config.yaml");
    write_file(config_path, "oauth: { issuer: " + issuer + " }\n");
    serving.emplace(workspace, node.state, node.credentials, std::nullopt, std::vector<std::string>{"--config", config_path.string()}, port);
    ASSERT_TRUE(serving->up()) << serving->log();
    root.port = port;
    root.sign_in_and_enrol(password);
    ASSERT_FALSE(HasFatalFailure());
    register_service();
  }

  // A service of the relying party's: private_key_jwt with its own key, client credentials for
  // reading the directory through the API.
  void register_service() {
    boost::json::object app;
    app["name"] = "Relying party";
    app["kind"] = "service";
    app["client_authentication"] = "private_key_jwt";
    app["jwks"] = client::testing::jwks(*service_key, "rp1");
    app["grant_types"] = boost::json::array{"client_credentials"};
    app["client_scopes"] = boost::json::array{"lugh:directory.read"};
    app["audiences"] = boost::json::array{"lugh"};
    const auto made = root.api(http::verb::post, "/api/v1/apps", boost::json::serialize(app));
    ASSERT_TRUE(made);
    ASSERT_EQ(made->status, 201u) << made->body;
    client_id = std::string(boost::json::parse(made->body).at("client_id").as_string());
  }

  // Runs the client's io_context until `done` holds, or ten seconds pass.
  template <typename Predicate>
  bool pump(Predicate done) {
    const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!done() && std::chrono::steady_clock::now() < until) {
      io.restart();
      io.run_for(std::chrono::milliseconds(20));
    }
    return done();
  }

  template <typename T>
  lugh::Outcome<T> wait(std::function<void(lugh::Done<lugh::Outcome<T>>)> call) {
    std::optional<lugh::Outcome<T>> out;
    call([&](lugh::Outcome<T> answer) { out = std::move(answer); });
    pump([&] { return out.has_value(); });
    if (!out) return lugh::Outcome<T>::failure(lugh::Fault::failed, "no answer within ten seconds");
    return std::move(*out);
  }

  Workspace workspace;
  Initialised node{workspace};
  std::optional<Serving> serving;
  RootBrowser root;
  std::filesystem::path config_path;
  std::string password;
  std::string issuer;
  std::string client_id;
  std::shared_ptr<const dannan::identity::SigningKey> service_key =
      std::make_shared<dannan::identity::SigningKey>(dannan::identity::SigningKey::generate(dannan::identity::SigningAlgorithm::es256));

  boost::asio::io_context io;
  // The relying party trusts the workspace's certificate, which says "localhost".
  client::HttpsClient https{io, workspace.certificate.string()};
};

}  // namespace

TEST_F(NodeProcessClient, ARelyingPartyAgainstTheRealNode) {
  const auto& wall = dannan::contract::system_wall_clock();

  // The key source reads the node's discovery and JWKS.
  client::Verifier verifier({issuer}, wall);
  auto keys = client::HttpsKeySource::make(verifier, https, io.get_executor(), dannan::contract::steady_time_source(), {});
  keys->start();
  ASSERT_TRUE(pump([&] { return keys->status().front().state == client::HttpsKeySource::State::fresh; })) << keys->status().front().last_error;
  EXPECT_GE(keys->status().front().keys, 1u);

  // The endpoints, from the same discovery document.
  client::HttpsRequest discovery;
  discovery.url = issuer + "/.well-known/openid-configuration";
  const auto document = wait<client::HttpsResponse>([&](auto done) { https.send(discovery, kCall, io.get_executor(), done); });
  ASSERT_TRUE(document.ok()) << document.message;
  const auto endpoints = client::Endpoints::from_discovery(boost::json::parse(document.value.body).as_object(), issuer);
  ASSERT_TRUE(std::holds_alternative<client::Endpoints>(endpoints)) << std::get<std::string>(endpoints);

  // Client credentials, the client proving itself with an assertion.
  client::ClientIdentity identity;
  identity.client_id = client_id;
  identity.method = client::ClientIdentity::Method::private_key_jwt;
  identity.key = service_key;
  identity.kid = "rp1";
  client::OAuthClient oauth(std::get<client::Endpoints>(endpoints), identity, https, verifier, wall);
  const auto tokens = wait<client::TokenSet>([&](auto done) { oauth.client_credentials({"lugh:directory.read"}, kCall, io.get_executor(), done); });
  ASSERT_TRUE(tokens.ok()) << tokens.message;
  const auto& access = *tokens.value.access_token;
  const std::string token(access.reveal().begin(), access.reveal().end());

  // Verified offline, as the node signed it.
  const auto checked = verifier.verify_access(token, "lugh");
  ASSERT_TRUE(std::holds_alternative<client::AccessToken>(checked)) << std::get<std::string>(checked);
  EXPECT_EQ(std::get<client::AccessToken>(checked).client_id, client_id);
  EXPECT_EQ(std::get<client::AccessToken>(checked).scopes, std::vector<std::string>{"lugh:directory.read"});

  // The management API answers it.
  client::ApiClient api(issuer, tokens.value.access_token, https, wall);
  const auto users = wait<client::ApiAnswer>([&](auto done) { api.call({"GET", "/users", std::nullopt, ""}, kCall, io.get_executor(), done); });
  ASSERT_TRUE(users.ok()) << users.message;
  EXPECT_EQ(users.value.status, 200u);

  // Active, then revoked: introspection says so; the offline verifier cannot know.
  const auto before = wait<client::Introspection>([&](auto done) { oauth.introspect(access, kCall, io.get_executor(), done); });
  ASSERT_TRUE(before.ok()) << before.message;
  EXPECT_TRUE(before.value.active);
  EXPECT_EQ(before.value.client_id, client_id);
  ASSERT_TRUE(wait<lugh::Nothing>([&](auto done) { oauth.revoke(access, kCall, io.get_executor(), done); }).ok());
  const auto after = wait<client::Introspection>([&](auto done) { oauth.introspect(access, kCall, io.get_executor(), done); });
  ASSERT_TRUE(after.ok()) << after.message;
  EXPECT_FALSE(after.value.active);
  EXPECT_TRUE(std::holds_alternative<client::AccessToken>(verifier.verify_access(token, "lugh")));
  const auto refused = wait<client::ApiAnswer>([&](auto done) { api.call({"GET", "/users", std::nullopt, ""}, kCall, io.get_executor(), done); });
  EXPECT_EQ(refused.fault, lugh::Fault::refused);

  // The stop runs on the key source's strand; a moment's running lets it.
  keys->stop();
  for (int i = 0; i < 5; ++i) {
    io.restart();
    io.run_for(std::chrono::milliseconds(20));
  }
  const auto text = serving->stop();
  EXPECT_EQ(text.find(token), std::string::npos) << "an access token is never logged";
}
