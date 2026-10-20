#include "crypto/digest.h"

#include <openssl/evp.h>

#include <stdexcept>

namespace lugh::crypto {

std::array<unsigned char, kSha256Bytes> sha256(std::span<const unsigned char> data) {
  std::array<unsigned char, kSha256Bytes> out{};
  unsigned int length = 0;
  // EVP_Digest fails only when OpenSSL cannot allocate or has no SHA-256 at all; neither is
  // something a caller can recover from, so it is the one throw here.
  if (EVP_Digest(data.data(), data.size(), out.data(), &length, EVP_sha256(), nullptr) != 1 || length != kSha256Bytes) {
    throw std::runtime_error("SHA-256 is not available");
  }
  return out;
}

}  // namespace lugh::crypto
