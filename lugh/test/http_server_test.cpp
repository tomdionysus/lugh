//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/http/http_server.h"

#include <gtest/gtest.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <boost/json.hpp>
#include <stdexcept>
#include <thread>

#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"
#include "lugh/http/api_json.h"
#include "lugh/http/client_certificate.h"
#include "lugh/test/fixtures/recording_sink.h"
#include "lugh/test/fixtures/temp_directory.h"
#include "lugh/test/fixtures/test_certificate.h"

using lugh::http::ClientAddress;
using lugh::http::HttpMiddleware;
using lugh::http::HttpPipeline;
using lugh::http::HttpRequest;
using lugh::http::HttpResponse;
using lugh::http::HttpServer;
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
  std::shared_ptr<RecordingSink> logger = std::make_shared<RecordingSink>();
  std::shared_ptr<HttpServer> server;
  std::thread thread;

  // With `mtls`, the listener asks for client certificates, chained to `client_ca` if given.
  explicit Running(std::vector<HttpMiddleware> middlewares, HttpPipeline::Limits limits = {}, bool mtls = false, const std::string& client_ca = "") {
    TestCertificate pair;
    const auto certificates = std::make_shared<dannan::listen::Certificates>(
        dannan::listen::CertificatePaths{dir.write("cert.pem", pair.certificate_pem), dir.write("key.pem", pair.key_pem),
                                         client_ca.empty() ? std::filesystem::path() : dir.write("ca.pem", client_ca)});

    server =
        std::make_shared<HttpServer>(logger, io_context, certificates, std::make_shared<ClientAddress>(std::vector<lugh::network::Prefix>{}), limits, mtls);
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

  // With `certificate`, the client presents it (a TestCertificate's PEM pair).
  explicit Client(std::uint16_t port, int max_version = TLS1_3_VERSION, const TestCertificate* certificate = nullptr)
      : stream(_prepared(max_version, certificate), context) {
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
  beast::tcp_stream _prepared(int max_version, const TestCertificate* certificate) {
    context.set_verify_mode(ssl::verify_none);
    if (certificate) {
      context.use_certificate(net::buffer(certificate->certificate_pem), ssl::context::pem);
      context.use_private_key(net::buffer(certificate->key_pem), ssl::context::pem);
    }
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

namespace {

std::shared_ptr<dannan::listen::Certificates> certificates_in(const TempDirectory& dir) {
  TestCertificate pair;
  return std::make_shared<dannan::listen::Certificates>(
      dannan::listen::CertificatePaths{dir.write("cert.pem", pair.certificate_pem), dir.write("key.pem", pair.key_pem), {}});
}

}  // namespace

TEST(HttpServer, ListeningOnNonsenseFails) {
  TempDirectory dir;
  net::io_context io_context;
  auto server = std::make_shared<HttpServer>(std::make_shared<RecordingSink>(), io_context, certificates_in(dir),
                                             std::make_shared<ClientAddress>(std::vector<lugh::network::Prefix>{}));

  const auto status = server->listen("not-an-address", 0);
  EXPECT_FALSE(status.ok);
  EXPECT_NE(status.error.find("not-an-address"), std::string::npos);
}

TEST(HttpServer, APortInUseFails) {
  Running running({});

  TempDirectory dir;
  net::io_context io_context;
  auto second = std::make_shared<HttpServer>(std::make_shared<RecordingSink>(), io_context, certificates_in(dir),
                                             std::make_shared<ClientAddress>(std::vector<lugh::network::Prefix>{}));

  EXPECT_FALSE(second->listen("127.0.0.1", running.server->port()).ok);
}

namespace {

// What the routes were told of the client's certificate, as the body.
HttpMiddleware certificate_echo() {
  return [](const HttpRequest& request, const std::string&, std::shared_ptr<HttpResponse> response, std::function<void(bool)> next) {
    const auto certificate = lugh::http::client_certificate(request);
    response->body() = certificate ? certificate->thumbprint + "|" + certificate->subject + "|" + (certificate->verified ? "verified" : "unverified") : "none";
    next(false);
  };
}

// The x5t#S256 of a PEM certificate: the SHA-256 of its DER, base64url (RFC 8705 section 3.1).
std::string thumbprint_of(const std::string& pem) {
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  X509* certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  unsigned char* der = nullptr;
  const int length = i2d_X509(certificate, &der);
  const auto out = lugh::encoding::base64url(dannan::identity::sha256({der, static_cast<std::size_t>(length)}).bytes);
  OPENSSL_free(der);
  X509_free(certificate);
  BIO_free(bio);
  return out;
}

}  // namespace

// RFC 8705: the certificate a client presents on the mTLS listener reaches the routes.
TEST(HttpServer, TheMtlsListenerHandsOnTheClientCertificate) {
  TestCertificate client_pair;
  {
    Running running({certificate_echo()}, {}, true);
    Client client(running.server->port(), TLS1_3_VERSION, &client_pair);
    EXPECT_EQ(client.send(get("/")).body(), thumbprint_of(client_pair.certificate_pem) + "|CN=localhost|unverified");
    // A connection without one is served all the same.
    Client plain(running.server->port());
    EXPECT_EQ(plain.send(get("/")).body(), "none");
  }
  // Chained to the configured client CA, it is verified (a self-signed certificate is its own).
  Running running({certificate_echo()}, {}, true, client_pair.certificate_pem);
  Client client(running.server->port(), TLS1_3_VERSION, &client_pair);
  EXPECT_EQ(client.send(get("/")).body(), thumbprint_of(client_pair.certificate_pem) + "|CN=localhost|verified");
  // Another certificate is not.
  TestCertificate stranger;
  Client other(running.server->port(), TLS1_3_VERSION, &stranger);
  EXPECT_NE(other.send(get("/")).body().find("|unverified"), std::string::npos);
}

// Only the server says what certificate a client presented: a client's own claim is dropped.
TEST(HttpServer, AClientCannotClaimACertificate) {
  for (const bool mtls : {false, true}) {
    Running running({certificate_echo()}, {}, mtls);
    Client client(running.server->port());
    auto request = get("/");
    request.set(lugh::http::kCertificateThumbprint, "forged");
    request.set(lugh::http::kCertificateSubject, "CN=admin");
    request.set(lugh::http::kCertificateChain, "verified");
    EXPECT_EQ(client.send(request).body(), "none") << mtls;
  }
}
