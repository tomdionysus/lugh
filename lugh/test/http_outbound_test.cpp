//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <atomic>
#include <mutex>
#include <thread>

#include "lugh/http/http_server.h"
#include "lugh/http/outbound.h"
#include "lugh/http/tls_context.h"
#include "lugh/test/fixtures/recording_sink.h"
#include "lugh/test/fixtures/temp_directory.h"
#include "lugh/test/fixtures/test_certificate.h"

namespace http = lugh::http;
namespace net = lugh::http::net;

namespace {

constexpr lugh::Deadline kDeadline = std::chrono::seconds(10);

// A real HTTPS server on 127.0.0.1 whose certificate says "localhost", and the client's own
// io_context beside it.
class OutboundTest : public ::testing::Test {
 protected:
  void SetUp() override {
    roots = dir.write("roots.pem", pair.certificate_pem).string();
    const auto tls = http::TlsContext::server(dir.write("cert.pem", pair.certificate_pem).string(), dir.write("key.pem", pair.key_pem).string());
    ASSERT_TRUE(tls.ok) << tls.error;
    server = std::make_shared<http::HttpServer>(std::make_shared<RecordingSink>(), server_io, tls.value,
                                                std::make_shared<http::ClientAddress>(std::vector<lugh::network::Cidr>{}));
    server->middleware_add(
        [this](const http::HttpRequest& request, const std::string&, std::shared_ptr<http::HttpResponse> response, std::function<void(bool)> next) {
          std::lock_guard held(_seen_mutex);
          _seen = {request.body(), std::string(request[http::field::content_type]), std::string(request.target())};
          response->result(static_cast<http::status>(answer_with.load()));
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

  lugh::Outcome<unsigned> post(const std::string& url, const std::string& ca) {
    net::io_context client_io;
    auto outbound = std::make_shared<http::HttpsOutbound>(client_io, ca);
    std::optional<lugh::Outcome<unsigned>> out;
    outbound->post_form(url, "logout_token=abc", kDeadline, client_io.get_executor(), [&](lugh::Outcome<unsigned> answer) { out = std::move(answer); });
    client_io.run();
    return *out;
  }

  TempDirectory dir;
  TestCertificate pair;
  std::string roots;
  std::string port;
  net::io_context server_io;
  std::shared_ptr<http::HttpServer> server;
  std::thread server_thread;
  std::atomic<unsigned> answer_with{200};

  // What the server last took, written on its thread.
  struct Seen {
    std::string body;
    std::string type;
    std::string target;
  };
  Seen seen() {
    std::lock_guard held(_seen_mutex);
    return _seen;
  }

 private:
  std::mutex _seen_mutex;
  Seen _seen;
};

}  // namespace

TEST(OutboundTarget, TakesAnHttpsUrlApart) {
  const auto plain = http::outbound_target("https://client.example.com/logout?x=1");
  ASSERT_TRUE(plain);
  EXPECT_EQ(plain->host, "client.example.com");
  EXPECT_EQ(plain->port, "443");
  EXPECT_EQ(plain->target, "/logout?x=1");
  const auto port = http::outbound_target("https://client.example.com:8443");
  ASSERT_TRUE(port);
  EXPECT_EQ(port->port, "8443");
  EXPECT_EQ(port->target, "/");
  const auto literal = http::outbound_target("https://[::1]:8443/x");
  ASSERT_TRUE(literal);
  EXPECT_EQ(literal->host, "::1");
  EXPECT_EQ(literal->port, "8443");
}

TEST(OutboundTarget, RefusesAnythingElse) {
  EXPECT_FALSE(http::outbound_target("http://client.example.com/logout"));
  EXPECT_FALSE(http::outbound_target("https:///logout"));
  EXPECT_FALSE(http::outbound_target("https://client.example.com:/logout"));
  EXPECT_FALSE(http::outbound_target("https://[::1/logout"));
  EXPECT_FALSE(http::outbound_target("ftp://client.example.com/"));
  EXPECT_FALSE(http::outbound_target(""));
}

TEST_F(OutboundTest, PostsTheFormAndAnswersTheStatus) {
  answer_with = 204;
  const auto answer = post("https://localhost:" + port + "/backchannel?tenant=1", roots);
  ASSERT_TRUE(answer.ok()) << answer.message;
  EXPECT_EQ(answer.value, 204u);
  EXPECT_EQ(seen().body, "logout_token=abc");
  EXPECT_EQ(seen().type, "application/x-www-form-urlencoded");
  EXPECT_EQ(seen().target, "/backchannel?tenant=1");
}

// A refusal is an answer; what to do with it is the caller's.
TEST_F(OutboundTest, ARefusalIsAnAnswer) {
  answer_with = 500;
  const auto answer = post("https://localhost:" + port + "/", roots);
  ASSERT_TRUE(answer.ok()) << answer.message;
  EXPECT_EQ(answer.value, 500u);
}

TEST_F(OutboundTest, ACertificateFromAnotherRootIsRefused) {
  TestCertificate other;
  const auto answer = post("https://localhost:" + port + "/", dir.write("other.pem", other.certificate_pem).string());
  EXPECT_FALSE(answer.ok());
  EXPECT_TRUE(seen().body.empty());
}

// The right root, the wrong name: the certificate says localhost, and this asks for an address.
TEST_F(OutboundTest, ACertificateForAnotherNameIsRefused) {
  const auto answer = post("https://127.0.0.1:" + port + "/", roots);
  EXPECT_FALSE(answer.ok());
  EXPECT_TRUE(seen().body.empty());
}

TEST_F(OutboundTest, NotHttpsIsRefusedWithoutConnecting) {
  const auto answer = post("http://localhost:" + port + "/", roots);
  EXPECT_FALSE(answer.ok());
  EXPECT_TRUE(seen().body.empty());
}

TEST_F(OutboundTest, RootsThatCannotBeReadAreAnErrorAtTheStart) {
  net::io_context client_io;
  EXPECT_THROW(http::HttpsOutbound(client_io, (dir.path() / "nothing.pem").string()), std::runtime_error);
}
