//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <span>
#include <string_view>

#include "dannan/identity/crypto.h"
#include "dannan/identity/secure_memory.h"

// Bytes are Dannan's, for the whole stack (dannan/identity): Bytes anyone may see, and
// SecureBuffer for anything that holds a secret before it is sealed, on locked pages
// of its own, kept out of core dumps and wiped when freed, including when it grows.
namespace lugh {

using Bytes = dannan::identity::Bytes;
using SecureBuffer = dannan::identity::SecureBuffer;

inline std::span<const unsigned char> byte_span(std::string_view text) { return {reinterpret_cast<const unsigned char*>(text.data()), text.size()}; }

}  // namespace lugh
