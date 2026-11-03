//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "crypto/argon2.h"

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/params.h>

#include <memory>
#include <vector>

namespace lugh::crypto {

Result<SecureBytes> argon2id(const Argon2Params& params, std::span<const unsigned char> password, std::span<const unsigned char> salt, std::size_t length,
                             std::span<const unsigned char> secret, std::span<const unsigned char> associated) {
  using Answer = Result<SecureBytes>;
  if (!params.valid()) return Answer::failure("Argon2id costs out of range");
  if (salt.size() < kArgon2MinimumSalt) return Answer::failure("Argon2id needs a salt of at least 8 bytes");
  if (length < 4 || length > 1024) return Answer::failure("Argon2id makes 4 to 1024 bytes here");

  std::unique_ptr<EVP_KDF, decltype(&EVP_KDF_free)> kdf(EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr), &EVP_KDF_free);
  if (!kdf) return Answer::failure("Argon2id is not available: it needs OpenSSL 3.2 or newer");
  std::unique_ptr<EVP_KDF_CTX, decltype(&EVP_KDF_CTX_free)> context(EVP_KDF_CTX_new(kdf.get()), &EVP_KDF_CTX_free);
  if (!context) return Answer::failure("Argon2id: out of memory");

  // One thread: OpenSSL would need a thread pool set up process-wide for more, and the
  // lanes are computed in turn instead, to the same answer.
  std::uint32_t memory = params.memory_kib;
  std::uint32_t iterations = params.iterations;
  std::uint32_t lanes = params.lanes;
  std::uint32_t threads = 1;

  std::vector<OSSL_PARAM> list{
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<unsigned char*>(password.data()), password.size()),
      OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(salt.data()), salt.size()),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iterations),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memory),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes),
      OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_THREADS, &threads),
  };
  if (!secret.empty()) list.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SECRET, const_cast<unsigned char*>(secret.data()), secret.size()));
  if (!associated.empty()) {
    list.push_back(OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_ARGON2_AD, const_cast<unsigned char*>(associated.data()), associated.size()));
  }
  list.push_back(OSSL_PARAM_construct_end());

  SecureBytes out(length);
  if (EVP_KDF_derive(context.get(), out.data(), out.size(), list.data()) != 1) return Answer::failure("Argon2id failed");
  return Answer::success(std::move(out));
}

}  // namespace lugh::crypto
