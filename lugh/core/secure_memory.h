//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>

namespace lugh::secure_memory {

// Memory for key material. Each block is pages of its own, locked into RAM when the
// process's lock limit allows, so it is never swapped out; excluded from core dumps on
// Linux; zero when given and wiped when taken back. Under AddressSanitizer it is ordinary
// heap memory instead, still wiped, so ASan sees an overrun.
//
// Not OpenSSL's secure heap: OpenSSL's Argon2id takes its whole working memory from that
// heap once it exists, so it would have to be locked at 64 MiB and more per hash.
//
// nullptr when there is no memory.
void* allocate(std::size_t bytes);
void release(void* block, std::size_t bytes) noexcept;

// How many blocks could not be locked since the process started. main warns if any.
std::size_t unlocked();

}  // namespace lugh::secure_memory
