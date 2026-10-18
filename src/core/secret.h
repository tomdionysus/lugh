#pragma once

#include <openssl/crypto.h>

#include <cstddef>
#include <string>
#include <utility>

namespace lugh {

// A value that must never reach a log line, an error message or a response body: a key, a
// password, a token. It converts to nothing, so `logger->info("key " + secret)` does not
// compile, and the one way to the bytes is spelled out at the call site. The bytes are
// wiped when it goes. (std::string may leave an old buffer behind when it grows; the
// sealed store in P2 brings an allocator that does not.)
class Secret {
 public:
  // What a log line or error says in its place.
  static constexpr const char* kRedacted = "[redacted]";

  Secret() = default;
  explicit Secret(std::string value) : _value(std::move(value)) {}
  ~Secret() { _wipe(); }

  Secret(const Secret& other) = default;
  Secret(Secret&& other) noexcept : _value(std::move(other._value)) { other._clear(); }

  Secret& operator=(const Secret& other) {
    if (this != &other) {
      _wipe();
      _value = other._value;
    }
    return *this;
  }

  Secret& operator=(Secret&& other) noexcept {
    if (this != &other) {
      _wipe();
      _value = std::move(other._value);
      other._clear();
    }
    return *this;
  }

  // The bytes, for the code that hashes, seals or compares them. Nowhere else.
  const std::string& reveal() const { return _value; }

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
  void _wipe() {
    if (!_value.empty()) OPENSSL_cleanse(_value.data(), _value.size());
  }

  void _clear() {
    _wipe();
    _value.clear();
  }

  std::string _value;
};

}  // namespace lugh
