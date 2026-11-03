//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <cstring>

#include "lugh/core/secure_bytes.h"
#include "lugh/core/secure_memory.h"

namespace secure_memory = lugh::secure_memory;

TEST(SecureMemory, GivesZeroedMemory) {
  for (const std::size_t size : {std::size_t{1}, std::size_t{32}, std::size_t{4096}, std::size_t{70000}}) {
    auto* block = static_cast<unsigned char*>(secure_memory::allocate(size));
    ASSERT_NE(block, nullptr) << size;
    for (std::size_t i = 0; i < size; ++i) ASSERT_EQ(block[i], 0) << size << " at " << i;
    std::memset(block, 0xa5, size);
    secure_memory::release(block, size);
  }
}

TEST(SecureMemory, ZeroBytesIsStillABlock) {
  void* block = secure_memory::allocate(0);
  ASSERT_NE(block, nullptr);
  secure_memory::release(block, 0);
  secure_memory::release(nullptr, 10);
}

TEST(SecureMemory, RefusesTheImpossible) { EXPECT_EQ(secure_memory::allocate(static_cast<std::size_t>(-1)), nullptr); }

TEST(SecureMemory, SecureBytesGrowsThroughIt) {
  lugh::SecureBytes bytes;
  for (int i = 0; i < 10000; ++i) bytes.push_back(static_cast<unsigned char>(i));
  EXPECT_EQ(bytes.size(), 10000u);
  EXPECT_EQ(bytes[9999], static_cast<unsigned char>(9999));
}

// A test process's lock limit is small but not this small.
TEST(SecureMemory, SmallBlocksAreLocked) {
  const auto before = secure_memory::unlocked();
  void* block = secure_memory::allocate(64);
  secure_memory::release(block, 64);
  EXPECT_EQ(secure_memory::unlocked(), before);
}
