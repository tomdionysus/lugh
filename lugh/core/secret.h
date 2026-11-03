//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <openssl/crypto.h>

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "lugh/core/secure_bytes.h"

namespace lugh {

// A value that must never reach a log line, an error message or a response body: a
// password, a passphrase, a token. It converts to nothing, so `logger->info("key " + secret)`
// does not compile, and the one way to the bytes is spelled out at the call site. The bytes
// live in locked memory (dannan/identity/secure_memory.h) and are wiped when they go. Binary key
// material is SecureBuffer.
class Secret {
 public:
  // What a log line or error says in its place.
  static constexpr const char* kRedacted = "[redacted]";

  Secret() = default;

  // The string given is wiped once copied, so the caller's copy does not outlive this one.
  explicit Secret(std::string value) : _value(value.begin(), value.end()) {
    if (!value.empty()) OPENSSL_cleanse(value.data(), value.size());
  }

  Secret(const Secret& other) = default;
  Secret& operator=(const Secret& other) = default;

  Secret(Secret&& other) noexcept : _value(std::move(other._value)) { other._value.clear(); }

  Secret& operator=(Secret&& other) noexcept {
    if (this != &other) {
      _value = std::move(other._value);
      other._value.clear();
    }
    return *this;
  }

  // The bytes, for the code that hashes, seals or compares them. Nowhere else.
  std::string_view reveal() const { return {_value.data(), _value.size()}; }

  // For a reader that takes a secret a character at a time, so it is never whole anywhere
  // else.
  void push_back(char c) { _value.push_back(c); }

  bool empty() const { return _value.empty(); }
  std::size_t size() const { return _value.size(); }

  // Constant time over the bytes, so a comparison does not say how far it got. The lengths
  // are compared first, and that is known: a secret's length is not the secret.
  bool equals(const Secret& other) const {
    if (_value.size() != other._value.size()) return false;
    if (_value.empty()) return true;
    return CRYPTO_memcmp(_value.data(), other._value.data(), _value.size()) == 0;
  }

 private:
  std::vector<char, dannan::identity::SecureAllocator<char>> _value;
};

}  // namespace lugh
