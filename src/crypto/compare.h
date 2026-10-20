#pragma once

#include <openssl/crypto.h>

#include <span>

namespace lugh::crypto {

// Constant time over the bytes, for a MAC, a tag, a token or a hash: a comparison that
// stops early says how far an attacker's guess got. The lengths are compared first, and
// that is known.
inline bool equal(std::span<const unsigned char> a, std::span<const unsigned char> b) {
  if (a.size() != b.size()) return false;
  if (a.empty()) return true;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

}  // namespace lugh::crypto
