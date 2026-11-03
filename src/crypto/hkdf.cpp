//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "crypto/hkdf.h"

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <memory>
#include <vector>

namespace lugh::crypto {

Result<SecureBytes> hkdf_sha256(std::span<const unsigned char> key, std::span<const unsigned char> salt, std::span<const unsigned char> info,
                                std::size_t length) {
  using Answer = Result<SecureBytes>;
  if (key.empty()) return Answer::failure("HKDF needs a key");
  // RFC 5869: at most 255 blocks of the hash.
  if (length == 0 || length > 255 * 32) return Answer::failure("HKDF-SHA256 makes 1 to 8160 bytes");

  std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(EVP_KDF_fetch(nullptr, "HKDF", nullptr), &EVP_KDF_free);
  if (!kdf) return Answer::failure("HKDF is not available");
  std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> context(EVP_KDF_CTX_new(kdf.get()), &EVP_KDF_CTX_free);
  if (!context) return Answer::failure("HKDF: out of memory");

  // OpenSSL takes these as void* and does not write through them.
  char digest[] = "SHA256";
  std::vector<OSSL_PARAM> params{
      OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, digest, 0),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, const_cast<unsigned char*>(key.data()), key.size()),
  };
  if (!salt.empty()) params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(salt.data()), salt.size()));
  if (!info.empty()) params.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_INFO, const_cast<unsigned char*>(info.data()), info.size()));
  params.push_back(OSSL_PARAM_construct_end());

  SecureBytes out(length);
  if (EVP_KDF_derive(context.get(), out.data(), out.size(), params.data()) != 1) return Answer::failure("HKDF failed");
  return Answer::success(std::move(out));
}

}  // namespace lugh::crypto
