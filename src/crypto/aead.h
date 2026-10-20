#pragma once

#include <cstddef>
#include <optional>
#include <span>

#include "core/secure_bytes.h"
#include "core/status.h"
#include "system/random.h"

namespace lugh::crypto {

// AES-256-GCM, the one AEAD Lugh seals with, as Macha's journal does.
inline constexpr std::size_t kAeadKeyBytes = 32;
inline constexpr std::size_t kAeadNonceBytes = 12;
inline constexpr std::size_t kAeadTagBytes = 16;

// What a sealed value adds to its plaintext: the nonce in front, the tag behind.
inline constexpr std::size_t kAeadOverhead = kAeadNonceBytes + kAeadTagBytes;

// nonce || ciphertext || tag, under a fresh random nonce. The associated data is bound in
// but not carried: open() must be given the same, so a value sealed for one place cannot
// be opened as if it belonged to another.
//
// Random 96-bit nonces are safe to 2^32 seals under one key (NIST SP 800-38D); a key that
// may see more is rotated before it does.
Result<Bytes> seal(std::span<const unsigned char> key, std::span<const unsigned char> plaintext, std::span<const unsigned char> associated,
                   system::Random& random);

// nullopt for anything that is not what seal() made under this key and associated data:
// the wrong key, an edited byte, a truncation. It does not say which.
std::optional<SecureBytes> open(std::span<const unsigned char> key, std::span<const unsigned char> sealed, std::span<const unsigned char> associated);

// The primitive under seal() and open(), with the nonce the caller's: ciphertext || tag.
// For known-answer tests. A nonce used twice under one key gives the key away.
Result<Bytes> aes256gcm_encrypt(std::span<const unsigned char> key, std::span<const unsigned char> nonce, std::span<const unsigned char> plaintext,
                                std::span<const unsigned char> associated);
std::optional<SecureBytes> aes256gcm_decrypt(std::span<const unsigned char> key, std::span<const unsigned char> nonce,
                                             std::span<const unsigned char> ciphertext_and_tag, std::span<const unsigned char> associated);

}  // namespace lugh::crypto
