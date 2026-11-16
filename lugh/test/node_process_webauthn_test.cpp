//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// WebAuthn on the real binary, over TLS (TODO/2026-11-15-p11-webauthn.md, W7): a person enrols a
// passkey through an enrolment link, signs in with it alone, and still can after a restart; a
// cloned authenticator and a ceremony from another origin are refused.

#include <gtest/gtest.h>

#include "lugh/core/encoding.h"
#include "lugh/test/fixtures/node_browser.h"
#include "lugh/test/fixtures/soft_authenticator.h"

using namespace node_process;
namespace http = boost::beast::http;

namespace {

constexpr const char* kIssuer = "https://id.example.test";
constexpr const char* kRpId = "id.example.test";
constexpr const char* kPassword = "violet tractor under seven moons";

std::string b64(const std::vector<std::uint8_t>& bytes) { return lugh::encoding::base64url(bytes); }
std::string b64(std::string_view text) { return lugh::encoding::base64url({reinterpret_cast<const unsigned char*>(text.data()), text.size()}); }
std::string raw(std::string_view text) {
  const auto bytes = lugh::encoding::base64url_decode(text);
  return bytes ? std::string(bytes->begin(), bytes->end()) : std::string();
}

soft_authenticator::Authenticator for_lugh() {
  soft_authenticator::Authenticator out;
  out.rp_id = kRpId;
  out.origin = kIssuer;
  return out;
}

class NodeProcessWebAuthn : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_EQ(node.made.status, 0) << node.made.err;
    const auto password = root_password(node.made.err);
    ASSERT_FALSE(password.empty()) << node.made.err;
    config_path = workspace.path("config.yaml");
    write_file(config_path, std::string("oauth: { issuer: ") + kIssuer + " }\n");
    start();
    // Root's first sign-in enrols a passkey (offered beside TOTP), so root administers at phr.
    root.sign_in_and_enrol_passkey(password, kIssuer);
    ASSERT_FALSE(HasFatalFailure());
  }

  void start() {
    serving.emplace(workspace, node.state, node.credentials, std::nullopt, std::vector<std::string>{"--config", config_path.string()});
    ASSERT_TRUE(serving->up()) << serving->log();
    root.port = serving->port();
  }

  // Alice made by root through the API, and her enrolment link.
  std::string alice_with_link(std::string& token) {
    const auto made = root.api(http::verb::post, "/api/v1/users", R"({"name":"alice","email":"alice@example.test"})");
    EXPECT_TRUE(made && made->status == 201u) << (made ? made->body : "no answer");
    const auto id = std::string(boost::json::parse(made->body).at("id").as_string());
    const auto link = root.api(http::verb::post, "/api/v1/users/" + id + "/enrolment", "");
    EXPECT_TRUE(link && link->status == 201u) << (link ? link->body : "no answer");
    token = std::string(boost::json::parse(link->body).at("token").as_string());
    return id;
  }

  // The options a page's script fetches, with the visitor's CSRF token.
  boost::json::object options(RootBrowser& browser, const std::string& csrf, const std::string& purpose) {
    const auto answer = browser.browser(http::verb::post, "/signin/webauthn/options", R"({"purpose":")" + purpose + R"("})",
                                        {{"Content-Type", "application/json"}, {"X-CSRF-Token", csrf}});
    EXPECT_TRUE(answer && answer->status == 200u) << (answer ? answer->body : "no answer");
    return boost::json::parse(answer->body).as_object();
  }

  // From the link to a passkey: the password set, then the credential made and posted.
  void enrol(RootBrowser& browser, const std::string& token, soft_authenticator::Authenticator& authenticator) {
    const auto set = browser.browser(http::verb::get, "/signin/enrol/" + token);
    ASSERT_TRUE(set);
    const auto csrf = between(set->body, "name=\"csrf\" value=\"", "\"");
    const auto chosen =
        browser.browser(http::verb::post, "/signin/enrol/" + token, form({{"csrf", csrf}, {"password", kPassword}, {"password_again", kPassword}}));
    ASSERT_TRUE(chosen);
    ASSERT_EQ(chosen->header("Location"), "/signin/enrol/totp") << chosen->body;
    const auto page = browser.browser(http::verb::get, "/signin/enrol/totp");
    ASSERT_TRUE(page);
    ASSERT_NE(page->body.find("data-webauthn=\"enrol\""), std::string::npos);
    const auto enrol_csrf = between(page->body, "name=\"csrf\" value=\"", "\"");
    const auto made_options = options(browser, enrol_csrf, "enrol");
    const auto challenge = std::string(made_options.at("challenge").as_string());
    const auto created = authenticator.create(raw(challenge));
    const auto codes = browser.browser(http::verb::post, "/signin/webauthn",
                                       form({{"csrf", enrol_csrf},
                                             {"purpose", "enrol"},
                                             {"challenge", challenge},
                                             {"id", b64(authenticator.credential_id())},
                                             {"client_data", b64(created.client_data_json)},
                                             {"attestation_object", b64(created.attestation_object)},
                                             {"name", "laptop"}}));
    ASSERT_TRUE(codes);
    ASSERT_EQ(codes->status, 200u) << codes->body;
    ASSERT_NE(codes->body.find("recovery codes"), std::string::npos);
  }

  // A passkey sign-in in a fresh browser: no name, no password.
  std::optional<Reply> passkey(RootBrowser& browser, soft_authenticator::Authenticator& authenticator, const std::string& user_id) {
    const auto page = browser.browser(http::verb::get, "/signin");
    if (!page) return std::nullopt;
    const auto csrf = between(page->body, "name=\"csrf\" value=\"", "\"");
    const auto get_options = options(browser, csrf, "passkey");
    const auto challenge = std::string(get_options.at("challenge").as_string());
    const auto proof = authenticator.get(raw(challenge));
    return browser.browser(http::verb::post, "/signin/webauthn",
                           form({{"csrf", csrf},
                                 {"purpose", "passkey"},
                                 {"challenge", challenge},
                                 {"id", b64(authenticator.credential_id())},
                                 {"client_data", b64(proof.client_data_json)},
                                 {"authenticator_data", b64(proof.authenticator_data)},
                                 {"signature", b64(proof.signature)},
                                 {"user_handle", b64(user_id)}}));
  }

  std::string acr_of(RootBrowser& browser) {
    const auto me = browser.browser(http::verb::get, "/api/v1/me");
    EXPECT_TRUE(me && me->status == 200u) << (me ? me->body : "no answer");
    return std::string(boost::json::parse(me->body).at("session").at("acr").as_string());
  }

  Workspace workspace;
  Initialised node{workspace};
  std::optional<Serving> serving;
  RootBrowser root;
  std::filesystem::path config_path;
};

}  // namespace

TEST_F(NodeProcessWebAuthn, APasskeyEnrolledSignsInAloneAndOutlivesARestart) {
  std::string token;
  const auto alice = alice_with_link(token);
  auto authenticator = for_lugh();
  {
    RootBrowser enrolling(serving->port());
    enrol(enrolling, token, authenticator);
    ASSERT_FALSE(HasFatalFailure());
    EXPECT_EQ(acr_of(enrolling), "urn:lugh:acr:phr");
  }

  RootBrowser later(serving->port());
  const auto signed_in = passkey(later, authenticator, alice);
  ASSERT_TRUE(signed_in);
  ASSERT_EQ(signed_in->status, 303u) << signed_in->body;
  EXPECT_EQ(signed_in->header("Location"), "/signin/done");
  EXPECT_EQ(acr_of(later), "urn:lugh:acr:phr");

  // The credential is in the store: a restarted node knows it, and its count.
  serving->stop();
  serving.reset();
  start();
  ASSERT_FALSE(HasFatalFailure());
  RootBrowser after(serving->port());
  const auto again = passkey(after, authenticator, alice);
  ASSERT_TRUE(again);
  ASSERT_EQ(again->status, 303u) << again->body;
  EXPECT_EQ(acr_of(after), "urn:lugh:acr:phr");
}

TEST_F(NodeProcessWebAuthn, AClonedKeyAndAnotherOriginAreRefused) {
  std::string token;
  const auto alice = alice_with_link(token);
  auto authenticator = for_lugh();
  {
    RootBrowser enrolling(serving->port());
    enrol(enrolling, token, authenticator);
    ASSERT_FALSE(HasFatalFailure());
  }
  RootBrowser first(serving->port());
  ASSERT_EQ(passkey(first, authenticator, alice)->status, 303u);

  // A copy taken now, then the original used once more: the copy's next count repeats a used one.
  auto clone = authenticator;
  RootBrowser second(serving->port());
  ASSERT_EQ(passkey(second, authenticator, alice)->status, 303u);
  RootBrowser thief(serving->port());
  const auto cloned = passkey(thief, clone, alice);
  ASSERT_TRUE(cloned);
  EXPECT_EQ(cloned->status, 401u) << cloned->body;
  EXPECT_FALSE(thief.jar.has("__Host-lugh_session"));

  // A page on another site that relayed the ceremony: its origin is in the client data.
  auto phished = authenticator;
  phished.origin = "https://id.example.test.evil.example";
  RootBrowser elsewhere(serving->port());
  const auto relayed = passkey(elsewhere, phished, alice);
  ASSERT_TRUE(relayed);
  EXPECT_EQ(relayed->status, 401u) << relayed->body;
  EXPECT_FALSE(elsewhere.jar.has("__Host-lugh_session"));
}

// Root's first sign-in is offered a passkey as well as TOTP (the maintainer, 2026-11-16, P7): the passkey root
// enrolled there signs root in alone, at phr, which administering through a session needs.
TEST_F(NodeProcessWebAuthn, RootsFirstSignInMayEnrolAPasskey) {
  EXPECT_EQ(acr_of(root), "urn:lugh:acr:phr");
  RootBrowser later(serving->port());
  const auto signed_in = passkey(later, root.key, root.root_id);
  ASSERT_TRUE(signed_in);
  ASSERT_EQ(signed_in->status, 303u) << signed_in->body;
  EXPECT_EQ(acr_of(later), "urn:lugh:acr:phr");
  later.csrf_token = std::string(boost::json::parse(later.browser(http::verb::get, "/api/v1/me")->body).at("session").at("csrf_token").as_string());
  const auto made = later.api(http::verb::post, "/api/v1/groups", R"({"name":"operators"})");
  ASSERT_TRUE(made);
  EXPECT_EQ(made->status, 201u) << made->body;
}
