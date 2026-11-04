//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <algorithm>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include "lugh/http/http_server.h"
#include "lugh/http/tls_context.h"
#include "lugh/test/fixtures/node_browser.h"
#include "lugh/test/fixtures/recording_sink.h"
#include "lugh/tokens/jose.h"

// The whole of OAuth on the real binary, over TLS: root signs in and enrols; registers an
// application through the API; the application is consented to, gets a code, redeems it, reads
// userinfo and refreshes; and the sign-out reaches it, over a verified HTTPS post to a real
// server, and ends what it holds.

using namespace node_process;
namespace http = boost::beast::http;
namespace lhttp = lugh::http;

namespace {

constexpr const char* kRedirect = "https://client.example.test/cb";
constexpr const char* kAfter = "https://client.example.test/bye";
constexpr const char* kIssuer = "https://id.example.test";
constexpr const char* kVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
constexpr const char* kChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
constexpr auto kDeliveryWait = std::chrono::seconds(30);

std::string encoded(const std::string& text) { return dannan::encoding::percent_encode(text, dannan::encoding::PercentSet::unreserved()); }

std::string query_value(const std::string& uri, const std::string& name) {
  const auto question = uri.find('?');
  if (question == std::string::npos) return {};
  std::size_t at = question + 1;
  while (at < uri.size()) {
    const auto end = std::min(uri.find('&', at), uri.size());
    const auto part = uri.substr(at, end - at);
    const auto equals = part.find('=');
    if (part.substr(0, equals) == name) return dannan::encoding::percent_decode(part.substr(equals + 1), dannan::encoding::Decoding::form);
    at = end + 1;
  }
  return {};
}

// An application's back-channel URI: a real HTTPS server, on a thread of its own, with the
// workspace's certificate, which says "localhost".
class Receiver {
 public:
  explicit Receiver(const Workspace& workspace) {
    const auto tls = lhttp::TlsContext::server(workspace.certificate.string(), workspace.key.string());
    EXPECT_TRUE(tls.ok) << tls.error;
    _server = std::make_shared<lhttp::HttpServer>(std::make_shared<RecordingSink>(), _io, tls.value,
                                                  std::make_shared<lhttp::ClientAddress>(std::vector<lugh::network::Cidr>{}));
    _server->middleware_add(
        [this](const lhttp::HttpRequest& request, const std::string&, std::shared_ptr<lhttp::HttpResponse> response, std::function<void(bool)> next) {
          {
            std::lock_guard held(_mutex);
            _bodies.push_back(request.body());
          }
          _arrived.notify_all();
          response->result(http::status::ok);
          next(false);
        });
    const auto listening = _server->listen("127.0.0.1", 0);
    EXPECT_TRUE(listening.ok) << listening.error;
    _server->start();
    _thread = std::thread([this] { _io.run(); });
  }

  ~Receiver() {
    _server->stop();
    _io.stop();
    _thread.join();
  }

  std::string uri() const { return "https://localhost:" + std::to_string(_server->port()) + "/backchannel"; }

  // The first post's body once it has come; empty if none comes in time.
  std::string wait_for_post() {
    std::unique_lock held(_mutex);
    _arrived.wait_for(held, kDeliveryWait, [this] { return !_bodies.empty(); });
    return _bodies.empty() ? std::string() : _bodies.front();
  }

 private:
  boost::asio::io_context _io;
  std::shared_ptr<lhttp::HttpServer> _server;
  std::thread _thread;
  std::mutex _mutex;
  std::condition_variable _arrived;
  std::vector<std::string> _bodies;
};

class NodeProcessOAuth : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_EQ(node.made.status, 0) << node.made.err;
    password = root_password(node.made.err);
    ASSERT_FALSE(password.empty()) << node.made.err;
    config_path = workspace.path("config.yaml");
    write_file(config_path, std::string("oauth: { issuer: ") + kIssuer + ", outbound_ca: " + workspace.certificate.string() + " }\n");
    start();
    sign_in_and_enrol();
    register_application();
  }

  void start() {
    serving.emplace(workspace, node.state, node.credentials, std::nullopt, std::vector<std::string>{"--config", config_path.string()});
    ASSERT_TRUE(serving->up()) << serving->log();
  }

  // As a browser: cookies kept and sent, bodies typed.
  std::optional<Reply> browser(http::verb method, const std::string& target, const std::string& body = "",
                               std::vector<std::pair<std::string, std::string>> headers = {}) {
    if (!jar.header().empty()) headers.emplace_back("Cookie", jar.header());
    const bool typed = std::any_of(headers.begin(), headers.end(), [](const auto& one) { return one.first == "Content-Type"; });
    if (!body.empty() && !typed) headers.emplace_back("Content-Type", "application/x-www-form-urlencoded");
    auto reply = send(serving->port(), method, target, headers, body);
    if (reply) jar.keep(*reply);
    return reply;
  }

  // As the dashboard: JSON, with the session's CSRF token.
  std::optional<Reply> api(http::verb method, const std::string& target, const std::string& body) {
    return browser(method, target, body, {{"Content-Type", "application/json"}, {"X-CSRF-Token", csrf_token}});
  }

  // As the application, from its own server: no cookies.
  std::optional<Reply> client_call(const std::map<std::string, std::string>& fields) {
    return send(serving->port(), http::verb::post, "/oauth2/token", {{"Content-Type", "application/x-www-form-urlencoded"}}, form(fields));
  }

  void sign_in_and_enrol() {
    const auto page = browser(http::verb::get, "/signin");
    ASSERT_TRUE(page);
    const auto signed_password =
        browser(http::verb::post, "/signin", form({{"csrf", between(page->body, "name=\"csrf\" value=\"", "\"")}, {"login", "root"}, {"password", password}}));
    ASSERT_TRUE(signed_password);
    ASSERT_EQ(signed_password->header("Location"), "/signin/enrol/totp") << signed_password->body;
    const auto enrol = browser(http::verb::get, "/signin/enrol/totp");
    ASSERT_TRUE(enrol);
    secret = between(enrol->body, "<p class=\"secret\">", "</p>");
    std::erase(secret, ' ');
    const auto codes =
        browser(http::verb::post, "/signin/enrol/totp", form({{"csrf", between(enrol->body, "name=\"csrf\" value=\"", "\"")}, {"code", code_now(secret)}}));
    ASSERT_TRUE(codes);
    ASSERT_EQ(codes->status, 200u) << codes->body;
    const auto me = browser(http::verb::get, "/api/v1/me");
    ASSERT_TRUE(me);
    ASSERT_EQ(me->status, 200u) << me->body;
    const auto about = boost::json::parse(me->body);
    root_id = std::string(about.at("user").at("id").as_string());
    csrf_token = std::string(about.at("session").at("csrf_token").as_string());
  }

  void register_application() {
    const auto group = api(http::verb::post, "/api/v1/groups", R"({"name":"staff"})");
    ASSERT_TRUE(group);
    ASSERT_EQ(group->status, 201u) << group->body;
    const auto group_id = std::string(boost::json::parse(group->body).at("id").as_string());
    const auto member = api(http::verb::put, "/api/v1/groups/" + group_id + "/members/" + root_id, "");
    ASSERT_TRUE(member);
    ASSERT_EQ(member->status, 204u) << member->body;

    boost::json::object app;
    app["name"] = "Client";
    app["kind"] = "spa";
    app["client_authentication"] = "none";
    app["grant_types"] = boost::json::array{"authorization_code", "refresh_token"};
    app["redirect_uris"] = boost::json::array{kRedirect};
    app["post_logout_redirect_uris"] = boost::json::array{kAfter};
    app["backchannel_logout_uri"] = receiver.uri();
    app["scopes"] = boost::json::array{"openid", "profile", "offline_access"};
    const auto made = api(http::verb::post, "/api/v1/apps", boost::json::serialize(app));
    ASSERT_TRUE(made);
    ASSERT_EQ(made->status, 201u) << made->body;
    client_id = std::string(boost::json::parse(made->body).at("client_id").as_string());
    const auto access = api(http::verb::put, "/api/v1/apps/" + client_id + "/access/" + group_id, "");
    ASSERT_TRUE(access);
    ASSERT_EQ(access->status, 200u) << access->body;
  }

  // Consent and the code, then the code for tokens: what the application holds.
  void authorise() {
    const auto first = browser(http::verb::get, "/oauth2/authorize?response_type=code&client_id=" + client_id + "&redirect_uri=" + encoded(kRedirect) +
                                                    "&scope=openid%20profile%20offline_access&state=st8&nonce=n0nce&code_challenge=" + kChallenge +
                                                    "&code_challenge_method=S256");
    ASSERT_TRUE(first);
    ASSERT_EQ(first->status, 303u) << first->body;
    ASSERT_EQ(first->header("Location").rfind("/oauth2/consent?id=", 0), 0u) << first->header("Location");
    const auto page = browser(http::verb::get, first->header("Location"));
    ASSERT_TRUE(page);
    ASSERT_EQ(page->status, 200u) << page->body;

    const auto allowed = browser(
        http::verb::post, "/oauth2/consent",
        form(
            {{"csrf", between(page->body, "name=\"csrf\" value=\"", "\"")}, {"id", between(page->body, "name=\"id\" value=\"", "\"")}, {"decision", "allow"}}));
    ASSERT_TRUE(allowed);
    ASSERT_EQ(allowed->status, 200u) << allowed->body;
    auto back = between(allowed->body, "<a class=\"leaving\" href=\"", "\"");
    for (auto at = back.find("&amp;"); at != std::string::npos; at = back.find("&amp;", at + 1)) back.replace(at, 5, "&");
    ASSERT_EQ(back.rfind(kRedirect, 0), 0u) << back;
    EXPECT_EQ(query_value(back, "state"), "st8");
    EXPECT_EQ(query_value(back, "iss"), kIssuer);

    const auto tokens = client_call({{"grant_type", "authorization_code"},
                                     {"client_id", client_id},
                                     {"code", query_value(back, "code")},
                                     {"redirect_uri", kRedirect},
                                     {"code_verifier", kVerifier}});
    ASSERT_TRUE(tokens);
    ASSERT_EQ(tokens->status, 200u) << tokens->body;
    const auto body = boost::json::parse(tokens->body);
    access_token = std::string(body.at("access_token").as_string());
    id_token = std::string(body.at("id_token").as_string());
    refresh_token = std::string(body.at("refresh_token").as_string());
  }

  // A logout token, checked as the application would check it, against the published keys.
  void check_logout_token(const std::string& posted) {
    ASSERT_EQ(posted.rfind("logout_token=", 0), 0u) << posted;
    const auto token = lugh::tokens::jws_parse(posted.substr(13));
    ASSERT_TRUE(token);
    EXPECT_EQ(token->typ, "logout+jwt");

    const auto published = send(serving->port(), http::verb::get, "/oauth2/jwks");
    ASSERT_TRUE(published);
    std::vector<lugh::tokens::VerifyKey> keys;
    const auto jwks = boost::json::parse(published->body);
    for (const auto& one : jwks.at("keys").as_array()) keys.push_back(*lugh::tokens::from_jwk(one.as_object()));
    EXPECT_TRUE(lugh::tokens::jws_verify(*token, keys));

    const auto id = lugh::tokens::jws_parse(id_token);
    ASSERT_TRUE(id);
    EXPECT_EQ(token->claims.at("iss"), kIssuer);
    EXPECT_EQ(token->claims.at("aud"), boost::json::value(client_id));
    EXPECT_EQ(token->claims.at("sub"), boost::json::value(root_id));
    EXPECT_EQ(token->claims.at("sid"), id->claims.at("sid"));
    EXPECT_TRUE(token->claims.at("events").as_object().contains("http://schemas.openid.net/event/backchannel-logout"));
  }

  // The sign-out, from the application's own ID token, and what it leaves.
  void sign_out_and_check() {
    const auto cookie = jar.header();
    const auto out = browser(http::verb::get, "/oauth2/logout?id_token_hint=" + id_token + "&post_logout_redirect_uri=" + encoded(kAfter) + "&state=st9");
    ASSERT_TRUE(out);
    ASSERT_EQ(out->status, 303u) << out->body;
    EXPECT_EQ(out->header("Location"), std::string(kAfter) + "?state=st9");
    EXPECT_FALSE(jar.has("__Host-lugh_session"));

    const auto posted = receiver.wait_for_post();
    ASSERT_FALSE(posted.empty()) << "no back-channel logout arrived\n" << serving->log();
    check_logout_token(posted);

    // The old cookie opens nothing, and the application's refresh token is dead.
    const auto me = send(serving->port(), http::verb::get, "/api/v1/me", {{"Cookie", cookie}});
    ASSERT_TRUE(me);
    EXPECT_EQ(me->status, 401u);
    const auto refused = client_call({{"grant_type", "refresh_token"}, {"client_id", client_id}, {"refresh_token", refresh_token}});
    ASSERT_TRUE(refused);
    EXPECT_EQ(refused->status, 400u) << refused->body;
    EXPECT_EQ(boost::json::parse(refused->body).at("error"), "invalid_grant");
  }

  Workspace workspace;
  Initialised node{workspace};
  Receiver receiver{workspace};
  std::optional<Serving> serving;
  Jar jar;
  std::filesystem::path config_path;
  std::string password;
  std::string secret;
  std::string root_id;
  std::string csrf_token;
  std::string client_id;
  std::string access_token;
  std::string id_token;
  std::string refresh_token;
};

}  // namespace

TEST_F(NodeProcessOAuth, TheWholeFlow) {
  authorise();
  ASSERT_FALSE(HasFatalFailure());

  // The access token at userinfo, and refused without one.
  const auto info = send(serving->port(), http::verb::get, "/oauth2/userinfo", {{"Authorization", "Bearer " + access_token}});
  ASSERT_TRUE(info);
  ASSERT_EQ(info->status, 200u) << info->body;
  EXPECT_EQ(boost::json::parse(info->body).at("sub"), boost::json::value(root_id));
  const auto none = send(serving->port(), http::verb::get, "/oauth2/userinfo");
  ASSERT_TRUE(none);
  EXPECT_EQ(none->status, 401u);

  // A refresh: a new refresh token, which is the one from now on.
  const auto refreshed = client_call({{"grant_type", "refresh_token"}, {"client_id", client_id}, {"refresh_token", refresh_token}});
  ASSERT_TRUE(refreshed);
  ASSERT_EQ(refreshed->status, 200u) << refreshed->body;
  const auto newer = std::string(boost::json::parse(refreshed->body).at("refresh_token").as_string());
  EXPECT_NE(newer, refresh_token);
  refresh_token = newer;

  sign_out_and_check();
  ASSERT_FALSE(HasFatalFailure());

  const auto text = serving->stop();
  EXPECT_EQ(text.find(password), std::string::npos) << "root's password is never logged";
  EXPECT_EQ(text.find(secret), std::string::npos) << "nor the TOTP secret";
  EXPECT_EQ(text.find(refresh_token), std::string::npos) << "nor a refresh token";
  EXPECT_EQ(text.find(id_token), std::string::npos) << "nor an ID token";
}

// A node restarted still knows the session, and which application to tell when it ends.
TEST_F(NodeProcessOAuth, ARestartForgetsNeitherTheSessionNorItsApplications) {
  authorise();
  ASSERT_FALSE(HasFatalFailure());
  serving->stop();
  serving.reset();
  start();
  ASSERT_FALSE(HasFatalFailure());

  const auto me = browser(http::verb::get, "/api/v1/me");
  ASSERT_TRUE(me);
  ASSERT_EQ(me->status, 200u) << me->body;
  sign_out_and_check();
}
