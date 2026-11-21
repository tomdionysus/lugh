//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The operator's certificates are files the host renews (the maintainer, 2026-11-13); on SIGHUP the real
// binary reads them again for the next handshake (dannan::listen::Certificates::reload). A reload
// that fails keeps what was loaded, says which file, and never logs a key. The node keeps serving
// throughout, and still stops cleanly.

#include <gtest/gtest.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <csignal>
#include <thread>

#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"
#include "lugh/test/fixtures/node_process.h"
#include "lugh/test/fixtures/test_certificate.h"

namespace {

using namespace node_process;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;
namespace beast = boost::beast;

// The SHA-256 of a certificate's DER, base64url.
std::string thumbprint_of(X509* certificate) {
  unsigned char* der = nullptr;
  const int length = i2d_X509(certificate, &der);
  const auto out = lugh::encoding::base64url(dannan::identity::sha256({der, static_cast<std::size_t>(length)}).bytes);
  OPENSSL_free(der);
  return out;
}

std::string thumbprint_of_pem(const std::string& pem) {
  BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
  X509* certificate = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
  const auto out = thumbprint_of(certificate);
  X509_free(certificate);
  BIO_free(bio);
  return out;
}

// The thumbprint of the certificate the node presents on a new connection, or empty.
std::string presented(std::uint16_t port) {
  net::io_context io;
  ssl::context context(ssl::context::tls_client);
  context.set_verify_mode(ssl::verify_none);
  beast::ssl_stream<beast::tcp_stream> stream(io, context);
  boost::system::error_code ec;
  stream.next_layer().connect(net::ip::tcp::endpoint(net::ip::make_address("127.0.0.1"), port), ec);
  if (ec) return {};
  stream.handshake(ssl::stream_base::client, ec);
  if (ec) return {};
  X509* peer = SSL_get1_peer_certificate(stream.native_handle());
  if (!peer) return {};
  const auto out = thumbprint_of(peer);
  X509_free(peer);
  return out;
}

template <typename Predicate>
bool within_five_seconds(Predicate done) {
  const auto until = Clock::now() + std::chrono::seconds(5);
  while (!done() && Clock::now() < until) std::this_thread::sleep_for(std::chrono::milliseconds(100));
  return done();
}

}  // namespace

TEST(NodeProcess, SighupReloadsTheCertificates) {
  Workspace workspace;
  const auto state = workspace.path("state");
  const auto config = workspace.path("config.yaml");
  write_file(config, "log: { level: info }\ntls: { certificate: \"" + workspace.certificate.string() + "\", key: \"" + workspace.key.string() +
                         "\" }\nstate: { directory: \"" + state.string() + "\" }\n");
  const auto credentials = workspace.path("credentials");
  std::filesystem::create_directories(credentials);
  const auto made = run(workspace, {"init", "--config", config.string()});
  ASSERT_EQ(made.status, 0) << made.err;
  write_file(credentials / kCredential, made.out);

  const auto port = dannan::test::free_port();
  const auto log = workspace.path("serve.log");
  dannan::test::ChildProcess node({kBinary, "--config", config.string(), "--server-address", "127.0.0.1", "--server-port", std::to_string(port)}, log,
                                  {.environment = environment(credentials), .input = std::nullopt, .terminal = false});
  ASSERT_TRUE(wait_until_up(node, port, std::chrono::seconds(10))) << read_file(log);
  const auto first = thumbprint_of_pem(read_file(workspace.certificate));
  ASSERT_EQ(presented(port), first);

  // The host renews the files; SIGHUP; the next connection is given the new certificate.
  const TestCertificate renewed;
  write_file(workspace.certificate, renewed.certificate_pem);
  write_file(workspace.key, renewed.key_pem);
  node.signal(SIGHUP);
  const auto second = thumbprint_of_pem(renewed.certificate_pem);
  EXPECT_TRUE(within_five_seconds([&] { return presented(port) == second; })) << read_file(log);
  EXPECT_NE(read_file(log).find("Certificates reloaded from " + workspace.certificate.string()), std::string::npos) << read_file(log);

  // A key that is not one: the reload fails, says which file, and what was loaded stays.
  write_file(workspace.key, "not a key\n");
  node.signal(SIGHUP);
  EXPECT_TRUE(within_five_seconds([&] { return read_file(log).find("Certificates not reloaded") != std::string::npos; })) << read_file(log);
  EXPECT_NE(read_file(log).find(workspace.key.string()), std::string::npos) << read_file(log);
  EXPECT_EQ(presented(port), second);
  EXPECT_EQ(read_file(log).find("BEGIN"), std::string::npos) << "no key or certificate is ever logged";

  // Still serving, and still stops cleanly.
  const auto health = request(port, boost::beast::http::verb::get, "/health");
  ASSERT_TRUE(health);
  EXPECT_EQ(health->status, 200u);
  node.signal(SIGTERM);
  const auto status = node.wait(Clock::now() + std::chrono::seconds(5));
  ASSERT_TRUE(status.has_value()) << read_file(log);
  EXPECT_EQ(*status, 0) << read_file(log);
}

// At start the pair is checked before anything listens: a key that is not the certificate's, a
// file that is missing, or one that is not PEM stops the node, and the error names the file,
// never what is in it. What TlsContext's own tests proved, now proved on the binary.
TEST(NodeProcess, StartRefusesCertificatesThatWillNotServe) {
  Workspace workspace;
  const auto state = workspace.path("state");
  const auto key = workspace.path("key.pem");
  const auto config = workspace.path("config.yaml");
  write_file(config, "log: { level: info }\ntls: { certificate: \"" + workspace.certificate.string() + "\", key: \"" + key.string() +
                         "\" }\nstate: { directory: \"" + state.string() + "\" }\n");
  write_file(key, read_file(workspace.key));
  const auto credentials = workspace.path("credentials");
  std::filesystem::create_directories(credentials);
  const auto made = run(workspace, {"init", "--config", config.string()});
  ASSERT_EQ(made.status, 0) << made.err;
  write_file(credentials / kCredential, made.out);

  const auto serve = [&] {
    return run(workspace, {"--config", config.string(), "--server-address", "127.0.0.1", "--server-port", std::to_string(dannan::test::free_port())},
               {.environment = environment(credentials), .input = std::nullopt, .terminal = false});
  };

  const TestCertificate other;
  write_file(key, other.key_pem);
  const auto mismatched = serve();
  EXPECT_NE(mismatched.status, 0);
  EXPECT_NE(mismatched.err.find(key.string() + ": not the key of " + workspace.certificate.string()), std::string::npos) << mismatched.err;

  write_file(key, "not a key\n");
  const auto garbled = serve();
  EXPECT_NE(garbled.status, 0);
  EXPECT_NE(garbled.err.find(key.string() + ": not a PEM private key"), std::string::npos) << garbled.err;

  std::filesystem::remove(key);
  const auto missing = serve();
  EXPECT_NE(missing.status, 0);
  EXPECT_NE(missing.err.find(key.string()), std::string::npos) << missing.err;

  for (const auto* err : {&mismatched.err, &garbled.err, &missing.err}) EXPECT_EQ(err->find("BEGIN"), std::string::npos) << "no key is ever logged";
}
