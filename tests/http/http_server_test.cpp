//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "http/http_server.h"

#include <gtest/gtest.h>
#include <openssl/ssl.h>

#include <boost/json.hpp>
#include <stdexcept>
#include <thread>

#include "helpers/temp_directory.h"
#include "helpers/test_certificate.h"
#include "http/api_json.h"
#include "http/tls_context.h"
#include "mocks/logger_mock.h"

using lugh::http::ClientAddress;
using lugh::http::HttpMiddleware;
using lugh::http::HttpPipeline;
using lugh::http::HttpRequest;
using lugh::http::HttpResponse;
using lugh::http::HttpServer;
using lugh::http::TlsContext;
namespace http = lugh::http;
namespace net = lugh::http::net;
namespace beast = lugh::http::beast;
namespace ssl = lugh::http::ssl;

namespace {

// A real server on 127.0.0.1, on a port of its own, on a thread of its own, with a
// certificate of its own.
struct Running {
  TempDirectory dir;
  net::io_context io_context;
  std::shared_ptr<MockLogger> logger = std::make_shared<MockLogger>();
  std::shared_ptr<HttpServer> server;
  std::thread thread;

  explicit Running(std::vector<HttpMiddleware> middlewares, HttpPipeline::Limits limits = {}) {
    TestCertificate pair;
    const auto tls = TlsContext::server(dir.write("cert.pem", pair.certificate_pem).string(), dir.write("key.pem", pair.key_pem).string());
    EXPECT_TRUE(tls.ok) << tls.error;

    server = std::make_shared<HttpServer>(logger, io_context, tls.value, std::make_shared<ClientAddress>(std::vector<lugh::network::Cidr>{}), limits);
    for (auto& middleware : middlewares) server->middleware_add(std::move(middleware));

    const auto listening = server->listen("127.0.0.1", 0);
    EXPECT_TRUE(listening.ok) << listening.error;
    server->start();
    thread = std::thread([this] { io_context.run(); });
  }

  ~Running() {
    server->stop();
    io_context.stop();
    thread.join();
  }
};

// A TLS client connection that can send several requests in turn. It trusts whatever the
// server presents: these tests are about the server, not the chain.
struct Client {
  net::io_context io_context;
  ssl::context context{ssl::context::tls_client};
  beast::ssl_stream<beast::tcp_stream> stream;
  beast::flat_buffer buffer;

  explicit Client(std::uint16_t port, int max_version = TLS1_3_VERSION) : stream(_prepared(max_version), context) {
    stream.next_layer().connect(net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port));
    stream.handshake(ssl::stream_base::client);
  }

  HttpResponse send(HttpRequest request) {
    request.set(http::field::host, "127.0.0.1");
    request.prepare_payload();
    beast::http::write(stream, request);

    HttpResponse response;
    beast::http::read(stream, buffer, response);
    return response;
  }

  std::string negotiated() { return SSL_get_version(stream.native_handle()); }

 private:
  beast::tcp_stream _prepared(int max_version) {
    context.set_verify_mode(ssl::verify_none);
    SSL_CTX_set_max_proto_version(context.native_handle(), max_version);
    return beast::tcp_stream(io_context);
  }
};

HttpRequest get(const std::string& target) { return HttpRequest{http::verb::get, target, 11}; }

HttpMiddleware answer(const std::string& path, const std::string& body) {
  return [path, body](const HttpRequest& request, const std::string& remote, std::shared_ptr<HttpResponse> response, std::function<void(bool)> next) {
    if (request.target() != path) return next(true);
    response->body() = body + " from " + remote;
    next(false);
  };
}

}  // namespace

TEST(HttpServer, SpeaksTls13) {
  Running running({answer("/a", "x")});
  Client client(running.server->port());

  EXPECT_EQ(client.negotiated(), "TLSv1.3");
  EXPECT_EQ(client.send(get("/a")).result(), http::status::ok);
}

TEST(HttpServer, RefusesTls12) {
  Running running({answer("/a", "x")});
  EXPECT_THROW(Client(running.server->port(), TLS1_2_VERSION), boost::system::system_error);
}

TEST(HttpServer, RefusesPlaintext) {
  Running running({answer("/a", "x")});

  net::io_context io_context;
  beast::tcp_stream stream(io_context);
  stream.connect(net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), running.server->port()));
  beast::http::write(stream, get("/a"));

  // The server reads a TLS record and finds none; whatever comes back, it is not HTTP.
  beast::flat_buffer buffer;
  HttpResponse response;
  boost::system::error_code ec;
  beast::http::read(stream, buffer, response, ec);
  EXPECT_TRUE(ec) << response.result_int();
}

TEST(HttpServer, AnswersThroughTheChainInOrder) {
  Running running({answer("/a", "first"), answer("/b", "second")});
  Client client(running.server->port());

  EXPECT_EQ(client.send(get("/a")).body(), "first from 127.0.0.1");
  EXPECT_EQ(client.send(get("/b")).body(), "second from 127.0.0.1");
}

TEST(HttpServer, KeepsTheConnectionForTheNextRequest) {
  Running running({answer("/a", "x")});
  Client client(running.server->port());

  for (int i = 0; i < 3; ++i) {
    const auto response = client.send(get("/a"));
    EXPECT_EQ(response.result(), http::status::ok);
    EXPECT_TRUE(response.keep_alive());
  }
}

TEST(HttpServer, TheEndOfTheChainIsAJson404) {
  Running running({answer("/a", "x")});
  Client client(running.server->port());

  const auto response = client.send(get("/nothing"));
  EXPECT_EQ(response.result(), http::status::not_found);
  EXPECT_EQ(response.at(http::field::content_type), "application/json");
  EXPECT_EQ(boost::json::parse(response.body()).at("error").at("code").as_string(), "not_found");
}

TEST(HttpServer, EveryResponseCarriesTheSecurityHeaders) {
  Running running({answer("/a", "x")});
  Client client(running.server->port());

  for (const auto& response : {client.send(get("/a")), client.send(get("/nothing"))}) {
    EXPECT_EQ(response.at(http::field::server), "Lugh");
    EXPECT_EQ(response.at(http::field::strict_transport_security), "max-age=63072000; includeSubDomains");
    EXPECT_EQ(response.at("X-Content-Type-Options"), "nosniff");
    EXPECT_EQ(response.at("Referrer-Policy"), "no-referrer");
    EXPECT_NE(std::string(response.at("Content-Security-Policy")).find("frame-ancestors 'none'"), std::string::npos);
  }
}

TEST(HttpServer, AMiddlewareMayAnswerFromAnotherThread) {
  std::vector<std::thread> workers;
  {
    Running running({[&workers](const HttpRequest&, const std::string&, std::shared_ptr<HttpResponse> response, std::function<void(bool)> next) {
      workers.emplace_back([response, next] {
        response->body() = "later";
        next(false);
      });
    }});
    Client client(running.server->port());

    EXPECT_EQ(client.send(get("/")).body(), "later");
  }
  for (auto& worker : workers) worker.join();
}

TEST(HttpServer, AMiddlewareThatThrowsIs500AndLogged) {
  Running running({[](const HttpRequest&, const std::string&, std::shared_ptr<HttpResponse>, std::function<void(bool)>) { throw std::runtime_error("boom"); }});
  Client client(running.server->port());

  EXPECT_EQ(client.send(get("/x")).result(), http::status::internal_server_error);
  EXPECT_NE(running.logger->text().find("boom"), std::string::npos);
}

TEST(HttpServer, ABodyOverTheLimitIs413) {
  Running running({answer("/a", "x")}, {16, std::chrono::seconds(30), std::chrono::seconds(10)});
  Client client(running.server->port());

  HttpRequest request{http::verb::post, "/a", 11};
  request.body() = std::string(64, 'x');

  EXPECT_EQ(client.send(request).result(), http::status::payload_too_large);
}

TEST(HttpServer, ListeningOnNonsenseFails) {
  net::io_context io_context;
  auto tls = std::make_shared<ssl::context>(ssl::context::tls_server);
  auto server =
      std::make_shared<HttpServer>(std::make_shared<MockLogger>(), io_context, tls, std::make_shared<ClientAddress>(std::vector<lugh::network::Cidr>{}));

  const auto status = server->listen("not-an-address", 0);
  EXPECT_FALSE(status.ok);
  EXPECT_NE(status.error.find("not-an-address"), std::string::npos);
}

TEST(HttpServer, APortInUseFails) {
  Running running({});

  net::io_context io_context;
  auto tls = std::make_shared<ssl::context>(ssl::context::tls_server);
  auto second =
      std::make_shared<HttpServer>(std::make_shared<MockLogger>(), io_context, tls, std::make_shared<ClientAddress>(std::vector<lugh::network::Cidr>{}));

  EXPECT_FALSE(second->listen("127.0.0.1", running.server->port()).ok);
}
