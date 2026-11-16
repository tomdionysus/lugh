//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/test/fixtures/ldap_client.h"
#include "lugh/test/fixtures/node_browser.h"

// LDAP on the real binary. Root signs in and enrols through the pages, as it must; root's policy
// needs a second factor, so it makes an app password through the API; and that binds and reads over
// LDAPS and over StartTLS. Unconfigured, there is no listener at all.

using namespace node_process;
using ldap_client::Client;
namespace http = boost::beast::http;

namespace {

constexpr const char* kBase = "dc=example,dc=com";
constexpr const char* kRoot = "uid=root,ou=people,dc=example,dc=com";

class NodeProcessLdap : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_EQ(node.made.status, 0) << node.made.err;
    password = root_password(node.made.err);
    ASSERT_FALSE(password.empty()) << node.made.err;
    ldaps_port = dannan::test::free_port();
    plain_port = dannan::test::free_port();
    const auto config = workspace.path("config.yaml");
    // An issuer, so root's first sign-in can enrol a passkey and administer at phr.
    write_file(config, "ldap: { port: " + std::to_string(ldaps_port) + ", starttls_port: " + std::to_string(plain_port) + ", base_dn: '" + kBase +
                           "' }\noauth: { issuer: " + RootBrowser::kTestIssuer + " }\n");
    serving.emplace(workspace, node.state, node.credentials, std::nullopt, std::vector<std::string>{"--config", config.string()});
    ASSERT_TRUE(serving->up()) << serving->log();
    root.port = serving->port();
    root.sign_in_and_enrol_passkey(password);
    ASSERT_FALSE(HasFatalFailure());

    const auto made = root.api(http::verb::post, "/api/v1/me/app-passwords", R"({"name":"the test","scopes":["lugh:directory.read"]})");
    ASSERT_TRUE(made);
    ASSERT_EQ(made->status, 201u) << made->body;
    app_password = std::string(boost::json::parse(made->body).at("password").as_string());
  }

  void reads_as_root(Client& client) {
    const auto bound = client.bind(kRoot, app_password);
    ASSERT_TRUE(bound);
    ASSERT_EQ(bound->code, 0) << bound->message;
    EXPECT_EQ(client.extended(lugh::ldap::kWhoAmIOid)->value, std::string("dn:") + kRoot);

    const auto found = client.search(kBase, 2, {"memberOf"}, ldap_client::filter_equal("uid", "root"));
    ASSERT_TRUE(found);
    EXPECT_EQ(found->done.code, 0) << found->done.message;
    ASSERT_EQ(found->entries.size(), 1u);
    EXPECT_EQ(found->entries[0].dn, kRoot);
    // Genesis puts root in the administrators, which is where its scopes come from.
    EXPECT_FALSE(found->entries[0].attributes.at("memberOf").empty());
    EXPECT_EQ(client.compare(kRoot, "uid", "root")->code, static_cast<int>(lugh::ldap::ResultCode::compare_true));
  }

  Workspace workspace;
  Initialised node{workspace};
  std::optional<Serving> serving;
  RootBrowser root;
  std::string password;
  std::string app_password;
  std::uint16_t ldaps_port = 0;
  std::uint16_t plain_port = 0;
};

}  // namespace

TEST_F(NodeProcessLdap, OverLdaps) {
  Client client(ldaps_port, Client::Mode::ldaps);
  ASSERT_TRUE(client.connected);
  reads_as_root(client);
}

TEST_F(NodeProcessLdap, OverStartTls) {
  Client client(plain_port, Client::Mode::plaintext);
  ASSERT_TRUE(client.connected);
  // The rootDSE before anything, which is how a client learns StartTLS is there.
  const auto root_dse = client.search("", 0, {"supportedExtension"});
  ASSERT_TRUE(root_dse);
  ASSERT_EQ(root_dse->entries.size(), 1u);
  const auto& extensions = root_dse->entries[0].attributes.at("supportedExtension");
  EXPECT_NE(std::find(extensions.begin(), extensions.end(), lugh::ldap::kStartTlsOid), extensions.end());
  EXPECT_EQ(client.bind(kRoot, app_password)->code, static_cast<int>(lugh::ldap::ResultCode::confidentiality_required));

  ASSERT_TRUE(client.start_tls());
  reads_as_root(client);
}

// Root's policy asks for a second factor, which a bind cannot carry.
TEST_F(NodeProcessLdap, RootsMainPasswordIsRefused) {
  Client client(ldaps_port, Client::Mode::ldaps);
  const auto bound = client.bind(kRoot, password);
  ASSERT_TRUE(bound);
  EXPECT_EQ(bound->code, static_cast<int>(lugh::ldap::ResultCode::invalid_credentials));

  const auto text = serving->stop();
  EXPECT_EQ(text.find(password), std::string::npos) << "root's password is never logged";
  EXPECT_EQ(text.find(app_password), std::string::npos) << "nor an app password";
}

// A revoked app password stops a connection already bound with it.
TEST_F(NodeProcessLdap, RevokingStopsAConnectionAlreadyBound) {
  Client client(ldaps_port, Client::Mode::ldaps);
  reads_as_root(client);
  ASSERT_FALSE(HasFatalFailure());
  const auto listed = root.browser(http::verb::get, "/api/v1/me/app-passwords");
  ASSERT_TRUE(listed);
  const auto parsed = boost::json::parse(listed->body);
  const auto id = std::string(parsed.at("app_passwords").as_array().at(0).at("id").as_string());
  const auto revoked = root.api(http::verb::delete_, "/api/v1/me/app-passwords/" + id, "");
  ASSERT_TRUE(revoked);
  ASSERT_EQ(revoked->status, 204u) << revoked->body;
  EXPECT_EQ(client.extended(lugh::ldap::kWhoAmIOid)->value, "");
  EXPECT_EQ(client.bind(kRoot, app_password)->code, static_cast<int>(lugh::ldap::ResultCode::invalid_credentials));
}

// A provisioning tool: an app password that carries directory.write, its changes under its owner.
TEST_F(NodeProcessLdap, WritesThroughAnAppPasswordThatMay) {
  const auto made =
      root.api(http::verb::post, "/api/v1/me/app-passwords", R"({"name":"provisioning","scopes":["lugh:directory.read","lugh:directory.write"]})");
  ASSERT_TRUE(made);
  ASSERT_EQ(made->status, 201u) << made->body;
  const auto writing = std::string(boost::json::parse(made->body).at("password").as_string());

  Client client(ldaps_port, Client::Mode::ldaps);
  ASSERT_EQ(client.bind(kRoot, writing)->code, 0);
  const std::string entry = std::string("uid=dana,ou=people,") + kBase;
  const auto added = client.add(entry, {{"objectClass", {"inetOrgPerson"}}, {"cn", {"Dana"}}, {"sn", {"Dana"}}, {"mail", {"dana@example.com"}}});
  ASSERT_TRUE(added);
  ASSERT_EQ(added->code, 0) << added->message;
  EXPECT_EQ(client.modify(entry, "givenName", "Dana")->code, 0);

  // The API sees what LDAP wrote: one directory, two front ends.
  const auto listed = root.browser(http::verb::get, "/api/v1/users");
  ASSERT_TRUE(listed);
  EXPECT_NE(listed->body.find("dana@example.com"), std::string::npos);

  EXPECT_EQ(client.remove(entry)->code, 0);
  EXPECT_EQ(root.browser(http::verb::get, "/api/v1/users")->body.find("dana@example.com"), std::string::npos);

  // The read-only one may not.
  Client reader(ldaps_port, Client::Mode::ldaps);
  ASSERT_EQ(reader.bind(kRoot, app_password)->code, 0);
  EXPECT_EQ(reader.modify(kRoot, "cn", "x")->code, static_cast<int>(lugh::ldap::ResultCode::insufficient_access_rights));
  // And no app password changes the main one.
  EXPECT_EQ(client.password_modify(password, "a much better passphrase")->code, static_cast<int>(lugh::ldap::ResultCode::unwilling_to_perform));
}

// Root was made before anything could number it: the backfill does, and LDAP shows it.
TEST(NodeProcessLdapPosix, TheBackfillOnTheRealBinary) {
  Workspace workspace;
  const Initialised node(workspace);
  ASSERT_EQ(node.made.status, 0) << node.made.err;
  const auto ldaps_port = dannan::test::free_port();
  const auto config = workspace.path("config.yaml");
  write_file(config, "ldap: { port: " + std::to_string(ldaps_port) + ", base_dn: '" + kBase +
                         "', posix: { uid_range: 10000-19999, gid_range: 20000-29999, primary_group: administrators, shell: /bin/zsh } }\n" +
                         "oauth: { issuer: " + RootBrowser::kTestIssuer + " }\n");
  Serving serving(workspace, node.state, node.credentials, std::nullopt, {"--config", config.string()});
  ASSERT_TRUE(serving.up()) << serving.log();
  RootBrowser root(serving.port());
  // At phr: numbering the directory is administering.
  root.sign_in_and_enrol_passkey(root_password(node.made.err));
  ASSERT_FALSE(HasFatalFailure());

  const auto made = root.api(http::verb::post, "/api/v1/me/app-passwords", R"({"name":"the test"})");
  ASSERT_TRUE(made);
  ASSERT_EQ(made->status, 201u) << made->body;
  Client client(ldaps_port, Client::Mode::ldaps);
  ASSERT_EQ(client.bind(kRoot, std::string(boost::json::parse(made->body).at("password").as_string()))->code, 0);

  const auto before = client.search(kRoot, 0);
  ASSERT_EQ(before->entries.size(), 1u);
  EXPECT_EQ(before->entries[0].attributes.count("uidNumber"), 0u);

  const auto allocated = root.api(http::verb::post, "/api/v1/ldap/posix/allocate", "{}");
  ASSERT_TRUE(allocated);
  ASSERT_EQ(allocated->status, 200u) << allocated->body;
  EXPECT_EQ(boost::json::parse(allocated->body).at("users"), 1);

  const auto after = client.search(kRoot, 0);
  ASSERT_EQ(after->entries.size(), 1u);
  EXPECT_EQ(after->entries[0].attributes.at("uidNumber"), (std::vector<std::string>{"10000"}));
  EXPECT_EQ(after->entries[0].attributes.at("gidNumber").size(), 1u);
  EXPECT_EQ(after->entries[0].attributes.at("loginShell"), (std::vector<std::string>{"/bin/zsh"}));
}

// The setting reaches the listeners on the real binary.
TEST(NodeProcessLdapAnonymous, TheSetting) {
  const auto with = [](const std::string& setting, int expected) {
    Workspace workspace;
    const Initialised node(workspace);
    ASSERT_EQ(node.made.status, 0) << node.made.err;
    const auto plain_port = dannan::test::free_port();
    const auto config = workspace.path("config.yaml");
    write_file(config, "ldap: { starttls_port: " + std::to_string(plain_port) + ", base_dn: '" + kBase + "'" + setting + " }\n");
    Serving serving(workspace, node.state, node.credentials, std::nullopt, {"--config", config.string()});
    ASSERT_TRUE(serving.up()) << serving.log();
    Client client(plain_port, Client::Mode::plaintext);
    const auto bound = client.bind("", "");
    ASSERT_TRUE(bound);
    EXPECT_EQ(bound->code, expected) << setting;
  };
  with("", static_cast<int>(lugh::ldap::ResultCode::confidentiality_required));
  with(", anonymous_bind: false", static_cast<int>(lugh::ldap::ResultCode::confidentiality_required));
  with(", anonymous_bind: true", 0);
}

TEST(NodeProcessLdapOff, UnconfiguredThereIsNoListener) {
  Workspace workspace;
  const Initialised node(workspace);
  ASSERT_EQ(node.made.status, 0) << node.made.err;
  Serving serving(workspace, node.state, node.credentials);
  ASSERT_TRUE(serving.up()) << serving.log();
  EXPECT_EQ(serving.log().find("LDAP listening"), std::string::npos);
  // Nor is the backfill served without a range.
  EXPECT_EQ(send(serving.port(), http::verb::post, "/api/v1/ldap/posix/allocate")->status, 404u);
}
