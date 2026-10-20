#include "core/secure_memory.h"

#include <openssl/crypto.h>
#include <sys/mman.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <limits>
#include <new>

#if defined(__SANITIZE_ADDRESS__)
#define LUGH_SECURE_MEMORY_ON_HEAP 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define LUGH_SECURE_MEMORY_ON_HEAP 1
#endif
#endif

namespace lugh::secure_memory {

namespace {

std::atomic<std::size_t> unlocked_blocks{0};

std::size_t page_size() {
  static const auto size = static_cast<std::size_t>(::sysconf(_SC_PAGESIZE));
  return size;
}

#ifndef LUGH_SECURE_MEMORY_ON_HEAP
std::size_t mapped_size(std::size_t bytes) {
  const auto page = page_size();
  return (bytes + page - 1) / page * page;
}
#endif

}  // namespace

void* allocate(std::size_t bytes) {
  if (bytes == 0) bytes = 1;
  if (bytes > std::numeric_limits<std::size_t>::max() - page_size()) return nullptr;

#ifdef LUGH_SECURE_MEMORY_ON_HEAP
  void* block = ::operator new(bytes, std::nothrow);
  if (block != nullptr) std::memset(block, 0, bytes);
  return block;
#else
  const auto size = mapped_size(bytes);
  void* block = ::mmap(nullptr, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
  if (block == MAP_FAILED) return nullptr;

  if (::mlock(block, size) != 0) unlocked_blocks.fetch_add(1, std::memory_order_relaxed);
#ifdef MADV_DONTDUMP
  ::madvise(block, size, MADV_DONTDUMP);
#endif
  // An anonymous mapping starts as zeros.
  return block;
#endif
}

void release(void* block, std::size_t bytes) noexcept {
  if (block == nullptr) return;
  if (bytes == 0) bytes = 1;

#ifdef LUGH_SECURE_MEMORY_ON_HEAP
  OPENSSL_cleanse(block, bytes);
  ::operator delete(block);
#else
  const auto size = mapped_size(bytes);
  OPENSSL_cleanse(block, size);
  ::munlock(block, size);
  ::munmap(block, size);
#endif
}

std::size_t unlocked() { return unlocked_blocks.load(std::memory_order_relaxed); }

}  // namespace lugh::secure_memory
