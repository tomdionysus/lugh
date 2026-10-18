#include "http/tls_context.h"

#include <openssl/ssl.h>

namespace lugh::http {

Result<std::shared_ptr<ssl::context>> TlsContext::server(const std::string& certificate_path, const std::string& key_path) {
  using Answer = Result<std::shared_ptr<ssl::context>>;

  if (certificate_path.empty() || key_path.empty()) return Answer::failure("TLS needs both tls.certificate and tls.key: there is no plaintext listener");

  auto context = std::make_shared<ssl::context>(ssl::context::tls_server);
  boost::system::error_code ec;

  context->set_options(ssl::context::default_workarounds | ssl::context::no_sslv2 | ssl::context::no_sslv3 | ssl::context::no_tlsv1 | ssl::context::no_tlsv1_1 |
                           ssl::context::no_tlsv1_2 | ssl::context::no_compression | ssl::context::single_dh_use,
                       ec);
  if (ec) return Answer::failure("cannot set the TLS options: " + ec.message());

  // Beast's options name the versions to refuse; the floor says it the other way, so a
  // later OpenSSL that knows a version this does not cannot add it here.
  if (SSL_CTX_set_min_proto_version(context->native_handle(), TLS1_3_VERSION) != 1) return Answer::failure("cannot require TLS 1.3");
  SSL_CTX_set_options(context->native_handle(), SSL_OP_NO_RENEGOTIATION | SSL_OP_CIPHER_SERVER_PREFERENCE);

  context->use_certificate_chain_file(certificate_path, ec);
  if (ec) return Answer::failure("cannot read the TLS certificate " + certificate_path + ": " + ec.message());

  // OpenSSL checks the key against the certificate as it loads it, so an unreadable key and
  // one that belongs to another certificate both end here, each with its own reason.
  context->use_private_key_file(key_path, ssl::context::pem, ec);
  if (ec) return Answer::failure("cannot use the TLS key " + key_path + " with " + certificate_path + ": " + ec.message());

  if (SSL_CTX_check_private_key(context->native_handle()) != 1)
    return Answer::failure("tls.key " + key_path + " does not match tls.certificate " + certificate_path);

  return Answer::success(std::move(context));
}

}  // namespace lugh::http
