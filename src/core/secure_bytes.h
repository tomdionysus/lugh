#pragma once

#include <cstddef>
#include <new>
#include <span>
#include <string_view>
#include <vector>

#include "core/secure_memory.h"

namespace lugh {

// An allocator for key material, over secure_memory: locked pages of its own, kept out of
// core dumps, wiped as they are freed, including the old block a vector leaves behind when
// it grows.
template <typename T>
class SecureAllocator {
 public:
  using value_type = T;

  SecureAllocator() noexcept = default;
  template <typename U>
  SecureAllocator(const SecureAllocator<U>&) noexcept {}

  T* allocate(std::size_t count) {
    if (count > static_cast<std::size_t>(-1) / sizeof(T)) throw std::bad_array_new_length();
    void* block = secure_memory::allocate(count * sizeof(T));
    if (block == nullptr) throw std::bad_alloc();
    return static_cast<T*>(block);
  }

  void deallocate(T* block, std::size_t count) noexcept { secure_memory::release(block, count * sizeof(T)); }

  template <typename U>
  bool operator==(const SecureAllocator<U>&) const noexcept {
    return true;
  }
};

// Bytes anyone may see: a nonce, a salt, a sealed blob, a public key.
using Bytes = std::vector<unsigned char>;

// Bytes no one may: a key, a passphrase, anything before it is sealed.
using SecureBytes = std::vector<unsigned char, SecureAllocator<unsigned char>>;

inline std::span<const unsigned char> byte_span(std::string_view text) { return {reinterpret_cast<const unsigned char*>(text.data()), text.size()}; }

}  // namespace lugh
