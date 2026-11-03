//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>
#include <optional>
#include <span>

#include "lugh/core/secure_bytes.h"
#include "lugh/core/status.h"

// AES-256-GCM is Dannan's (dannan/identity/crypto.h). What is here is the form Lugh's
// keyring and store keep a sealed value in: the nonce, the ciphertext and the tag, in
// one run of bytes.
namespace lugh::crypto {

inline constexpr std::size_t kAeadKeyBytes = 32;
inline constexpr std::size_t kAeadNonceBytes = 12;
inline constexpr std::size_t kAeadTagBytes = 16;

// What a sealed value adds to its plaintext: the nonce in front, the tag behind.
inline constexpr std::size_t kAeadOverhead = kAeadNonceBytes + kAeadTagBytes;

// nonce || ciphertext || tag, under a fresh random nonce Dannan draws. The associated data
// is bound in but not carried: open() must be given the same, so a value sealed for one
// place cannot be opened as if it belonged to another.
Result<Bytes> seal(std::span<const unsigned char> key, std::span<const unsigned char> plaintext, std::span<const unsigned char> associated);

// The plaintext, in secure memory; nullopt for anything that is not what seal() made under
// this key and associated data: the wrong key, an edited byte, a truncation. It does not
// say which.
std::optional<SecureBuffer> open(std::span<const unsigned char> key, std::span<const unsigned char> sealed, std::span<const unsigned char> associated);

}  // namespace lugh::crypto
