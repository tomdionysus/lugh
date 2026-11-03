//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/crypto/aead.h"

#include <algorithm>
#include <exception>

#include "dannan/identity/crypto.h"

namespace lugh::crypto {

Result<Bytes> seal(std::span<const unsigned char> key, std::span<const unsigned char> plaintext, std::span<const unsigned char> associated) {
  using Answer = Result<Bytes>;
  if (key.size() != kAeadKeyBytes) return Answer::failure("an AES-256-GCM key is 32 bytes");
  try {
    const auto sealed = dannan::identity::aes_gcm_seal(key.first<kAeadKeyBytes>(), plaintext, associated);
    Bytes out(sealed.nonce.begin(), sealed.nonce.end());
    out.insert(out.end(), sealed.ciphertext.begin(), sealed.ciphertext.end());
    out.insert(out.end(), sealed.tag.begin(), sealed.tag.end());
    return Answer::success(std::move(out));
  } catch (const std::exception& e) {
    return Answer::failure(e.what());
  }
}

std::optional<SecureBuffer> open(std::span<const unsigned char> key, std::span<const unsigned char> sealed, std::span<const unsigned char> associated) {
  if (key.size() != kAeadKeyBytes || sealed.size() < kAeadOverhead) return std::nullopt;
  try {
    return dannan::identity::aes_gcm_open_secure(key.first<kAeadKeyBytes>(), sealed.first<kAeadNonceBytes>(), sealed.last<kAeadTagBytes>(),
                                                 sealed.subspan(kAeadNonceBytes, sealed.size() - kAeadOverhead), associated);
  } catch (const std::exception&) {
    return std::nullopt;
  }
}

}  // namespace lugh::crypto
