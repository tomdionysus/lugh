//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "crypto/aead.h"

#include <openssl/evp.h>

#include <climits>
#include <memory>

namespace lugh::crypto {

namespace {

using CipherContext = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

CipherContext new_context() { return CipherContext(EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free); }

bool fits_int(std::size_t size) { return size <= static_cast<std::size_t>(INT_MAX) - kAeadTagBytes; }

}  // namespace

Result<Bytes> aes256gcm_encrypt(std::span<const unsigned char> key, std::span<const unsigned char> nonce, std::span<const unsigned char> plaintext,
                                std::span<const unsigned char> associated) {
  using Answer = Result<Bytes>;
  if (key.size() != kAeadKeyBytes) return Answer::failure("AES-256-GCM needs a 32-byte key");
  if (nonce.size() != kAeadNonceBytes) return Answer::failure("AES-256-GCM needs a 12-byte nonce");
  if (!fits_int(plaintext.size()) || !fits_int(associated.size())) return Answer::failure("AES-256-GCM: input too large");

  auto context = new_context();
  if (!context) return Answer::failure("AES-256-GCM: out of memory");
  if (EVP_EncryptInit_ex2(context.get(), EVP_aes_256_gcm(), key.data(), nonce.data(), nullptr) != 1) return Answer::failure("AES-256-GCM: cannot start");

  int written = 0;
  if (!associated.empty() && EVP_EncryptUpdate(context.get(), nullptr, &written, associated.data(), static_cast<int>(associated.size())) != 1) {
    return Answer::failure("AES-256-GCM: cannot take the associated data");
  }

  Bytes out(plaintext.size() + kAeadTagBytes);
  int body = 0;
  if (!plaintext.empty() && EVP_EncryptUpdate(context.get(), out.data(), &body, plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
    return Answer::failure("AES-256-GCM: cannot encrypt");
  }

  int tail = 0;
  if (EVP_EncryptFinal_ex(context.get(), out.data() + body, &tail) != 1) return Answer::failure("AES-256-GCM: cannot finish");
  if (static_cast<std::size_t>(body + tail) != plaintext.size()) return Answer::failure("AES-256-GCM: short output");

  if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_GET_TAG, static_cast<int>(kAeadTagBytes), out.data() + plaintext.size()) != 1) {
    return Answer::failure("AES-256-GCM: cannot read the tag");
  }

  return Answer::success(std::move(out));
}

std::optional<SecureBytes> aes256gcm_decrypt(std::span<const unsigned char> key, std::span<const unsigned char> nonce,
                                             std::span<const unsigned char> ciphertext_and_tag, std::span<const unsigned char> associated) {
  if (key.size() != kAeadKeyBytes || nonce.size() != kAeadNonceBytes || ciphertext_and_tag.size() < kAeadTagBytes) return std::nullopt;
  if (!fits_int(ciphertext_and_tag.size()) || !fits_int(associated.size())) return std::nullopt;

  const auto ciphertext = ciphertext_and_tag.first(ciphertext_and_tag.size() - kAeadTagBytes);
  unsigned char tag[kAeadTagBytes];
  std::copy(ciphertext_and_tag.end() - kAeadTagBytes, ciphertext_and_tag.end(), tag);

  auto context = new_context();
  if (!context) return std::nullopt;
  if (EVP_DecryptInit_ex2(context.get(), EVP_aes_256_gcm(), key.data(), nonce.data(), nullptr) != 1) return std::nullopt;

  int written = 0;
  if (!associated.empty() && EVP_DecryptUpdate(context.get(), nullptr, &written, associated.data(), static_cast<int>(associated.size())) != 1) {
    return std::nullopt;
  }

  SecureBytes out(ciphertext.size());
  int body = 0;
  if (!ciphertext.empty() && EVP_DecryptUpdate(context.get(), out.data(), &body, ciphertext.data(), static_cast<int>(ciphertext.size())) != 1) {
    return std::nullopt;
  }

  if (EVP_CIPHER_CTX_ctrl(context.get(), EVP_CTRL_GCM_SET_TAG, static_cast<int>(kAeadTagBytes), tag) != 1) return std::nullopt;

  // The tag is checked here, and nothing decrypted is answered until it has been.
  int tail = 0;
  if (EVP_DecryptFinal_ex(context.get(), out.data() + body, &tail) != 1) return std::nullopt;
  if (static_cast<std::size_t>(body + tail) != ciphertext.size()) return std::nullopt;

  return out;
}

Result<Bytes> seal(std::span<const unsigned char> key, std::span<const unsigned char> plaintext, std::span<const unsigned char> associated,
                   system::Random& random) {
  using Answer = Result<Bytes>;

  const auto nonce = random.bytes(kAeadNonceBytes);
  if (nonce.size() != kAeadNonceBytes) return Answer::failure("no randomness for a nonce");

  auto body = aes256gcm_encrypt(key, nonce, plaintext, associated);
  if (!body.ok) return body;

  Bytes out;
  out.reserve(nonce.size() + body.value.size());
  out.insert(out.end(), nonce.begin(), nonce.end());
  out.insert(out.end(), body.value.begin(), body.value.end());
  return Answer::success(std::move(out));
}

std::optional<SecureBytes> open(std::span<const unsigned char> key, std::span<const unsigned char> sealed, std::span<const unsigned char> associated) {
  if (sealed.size() < kAeadOverhead) return std::nullopt;
  return aes256gcm_decrypt(key, sealed.first(kAeadNonceBytes), sealed.subspan(kAeadNonceBytes), associated);
}

}  // namespace lugh::crypto
