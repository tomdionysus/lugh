//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// lugh_client's HTTPS (docs/architecture.md, "Outbound"; TODO/2026-11-14-p10-plan.md, P10.2): an
// https URL taken apart; a request answered with its status, type, caching and body; headers and
// a body sent; an answer larger than the bound refused; nothing but GET and POST sent. The
// certificate and name checks are proven through the node's back-channel posts, which ride this
// client (http_outbound_test.cpp).

#include <gtest/gtest.h>

#include <mutex>
#include <thread>

#include "lugh/client/https.h"
#include "lugh/http/http_server.h"
#include "lugh/http/tls_context.h"
#include "lugh/test/fixtures/recording_sink.h"
#include "lugh/test/fixtures/temp_directory.h"
#include "lugh/test/fixtures/test_certificate.h"

namespace http = lugh::http;
namespace net = lugh::http::net;
using lugh::client::https_target;
using lugh::client::HttpsClient;
using lugh::client::HttpsRequest;
using lugh::client::HttpsResponse;

namespace {

constexpr lugh::Deadline kDeadline = std::chrono::seconds(10);

// A real HTTPS server on 127.0.0.1 whose certificate says "localhost", answering with what the
// test sets, and remembering what it was sent.
class HttpsTest : public ::testing::Test {
 protected:
  void SetUp() override {
    roots = dir.write("roots.pem", pair.certificate_pem).string();
    const auto tls = http::TlsContext::server(dir.write("cert.pem", pair.certificate_pem).string(), dir.write("key.pem", pair.key_pem).string());
    ASSERT_TRUE(tls.ok) << tls.error;
    server = std::make_shared<http::HttpServer>(std::make_shared<RecordingSink>(), server_io, tls.value,
                                                std::make_shared<http::ClientAddress>(std::vector<lugh::network::Cidr>{}));
    server->middleware_add(
        [this](const http::HttpRequest& request, const std::string&, std::shared_ptr<http::HttpResponse> response, std::function<void(bool)> next) {
          std::lock_guard held(_mutex);
          _seen = {std::string(request.method_string()), request.body(), std::string(request["X-Probe"])};
          response->result(http::status::ok);
          response->set(http::field::content_type, "application/json");
          response->set(http::field::cache_control, "max-age=600");
          response->body() = _answer_body;
          response->prepare_payload();
          next(false);
        });
    const auto listening = server->listen("127.0.0.1", 0);
    ASSERT_TRUE(listening.ok) << listening.error;
    port = std::to_string(server->port());
    server->start();
    server_thread = std::thread([this] { server_io.run(); });
  }

  void TearDown() override {
    server->stop();
    server_io.stop();
    server_thread.join();
  }

  lugh::Outcome<HttpsResponse> send(HttpsRequest request) {
    net::io_context client_io;
    HttpsClient client(client_io, roots);
    std::optional<lugh::Outcome<HttpsResponse>> out;
    client.send(std::move(request), kDeadline, client_io.get_executor(), [&](lugh::Outcome<HttpsResponse> answer) { out = std::move(answer); });
    client_io.run();
    return *out;
  }

  void answer_with(std::string body) {
    std::lock_guard held(_mutex);
    _answer_body = std::move(body);
  }

  struct Seen {
    std::string method;
    std::string body;
    std::string probe;
  };
  Seen seen() {
    std::lock_guard held(_mutex);
    return _seen;
  }

  TempDirectory dir;
  TestCertificate pair;
  std::string roots;
  std::string port;
  net::io_context server_io;
  std::shared_ptr<http::HttpServer> server;
  std::thread server_thread;

 private:
  std::mutex _mutex;
  Seen _seen;
  std::string _answer_body = R"({"keys":[]})";
};

}  // namespace

TEST(HttpsTarget, TakesAnHttpsUrlApart) {
  const auto plain = https_target("https://client.example.com/logout?x=1");
  ASSERT_TRUE(plain);
  EXPECT_EQ(plain->host, "client.example.com");
  EXPECT_EQ(plain->port, "443");
  EXPECT_EQ(plain->target, "/logout?x=1");
  const auto port = https_target("https://client.example.com:8443");
  ASSERT_TRUE(port);
  EXPECT_EQ(port->port, "8443");
  EXPECT_EQ(port->target, "/");
  const auto literal = https_target("https://[::1]:8443/x");
  ASSERT_TRUE(literal);
  EXPECT_EQ(literal->host, "::1");
  EXPECT_EQ(literal->port, "8443");
}

TEST(HttpsTarget, RefusesAnythingElse) {
  EXPECT_FALSE(https_target("http://client.example.com/logout"));
  EXPECT_FALSE(https_target("https:///logout"));
  EXPECT_FALSE(https_target("https://client.example.com:/logout"));
  EXPECT_FALSE(https_target("https://[::1/logout"));
  EXPECT_FALSE(https_target("ftp://client.example.com/"));
  EXPECT_FALSE(https_target(""));
}

TEST_F(HttpsTest, AGetIsAnsweredWithItsBody) {
  HttpsRequest request;
  request.url = "https://localhost:" + port + "/jwks";
  request.headers = {{"X-Probe", "p1"}};
  const auto answer = send(request);
  ASSERT_TRUE(answer.ok()) << answer.message;
  EXPECT_EQ(answer.value.status, 200u);
  EXPECT_EQ(answer.value.content_type, "application/json");
  EXPECT_EQ(answer.value.cache_control, "max-age=600");
  EXPECT_EQ(answer.value.body, R"({"keys":[]})");
  EXPECT_EQ(seen().method, "GET");
  EXPECT_EQ(seen().probe, "p1");
}

TEST_F(HttpsTest, APostCarriesItsBody) {
  HttpsRequest request;
  request.method = "POST";
  request.url = "https://localhost:" + port + "/token";
  request.content_type = "application/x-www-form-urlencoded";
  request.body = "grant_type=client_credentials";
  const auto answer = send(request);
  ASSERT_TRUE(answer.ok()) << answer.message;
  EXPECT_EQ(seen().method, "POST");
  EXPECT_EQ(seen().body, "grant_type=client_credentials");
}

TEST_F(HttpsTest, AnAnswerLargerThanTheBoundIsRefused) {
  answer_with(std::string(HttpsClient::kMostAnswerBytes + 1, 'x'));
  HttpsRequest request;
  request.url = "https://localhost:" + port + "/jwks";
  const auto answer = send(request);
  EXPECT_FALSE(answer.ok());
  EXPECT_EQ(answer.message, "the answer is larger than the bound");
}

TEST_F(HttpsTest, OnlyGetAndPostAreSent) {
  HttpsRequest request;
  request.method = "DELETE";
  request.url = "https://localhost:" + port + "/";
  const auto answer = send(request);
  EXPECT_FALSE(answer.ok());
  EXPECT_TRUE(seen().method.empty());
}
