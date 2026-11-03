//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "crypto/hmac.h"

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>

#include <memory>

namespace lugh::crypto {

Result<Bytes> hmac(HmacDigest digest, std::span<const unsigned char> key, std::span<const unsigned char> data) {
  using Answer = Result<Bytes>;
  if (key.empty()) return Answer::failure("HMAC needs a key");

  std::unique_ptr<EVP_MAC, decltype(&EVP_MAC_free)> mac(EVP_MAC_fetch(nullptr, "HMAC", nullptr), &EVP_MAC_free);
  if (!mac) return Answer::failure("HMAC is not available");
  std::unique_ptr<EVP_MAC_CTX, decltype(&EVP_MAC_CTX_free)> context(EVP_MAC_CTX_new(mac.get()), &EVP_MAC_CTX_free);
  if (!context) return Answer::failure("HMAC: out of memory");

  // OpenSSL takes the name as char* and does not write through it.
  char sha1[] = "SHA1";
  char sha256[] = "SHA256";
  const OSSL_PARAM params[] = {
      OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, digest == HmacDigest::sha1 ? sha1 : sha256, 0),
      OSSL_PARAM_construct_end(),
  };
  if (EVP_MAC_init(context.get(), key.data(), key.size(), params) != 1) return Answer::failure("HMAC failed");
  if (EVP_MAC_update(context.get(), data.data(), data.size()) != 1) return Answer::failure("HMAC failed");

  Bytes out(EVP_MAX_MD_SIZE);
  std::size_t length = 0;
  if (EVP_MAC_final(context.get(), out.data(), &length, out.size()) != 1) return Answer::failure("HMAC failed");
  out.resize(length);
  return Answer::success(std::move(out));
}

}  // namespace lugh::crypto
