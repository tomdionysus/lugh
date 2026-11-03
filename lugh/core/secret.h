//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <string>
#include <string_view>

#include "dannan/identity/crypto.h"
#include "dannan/identity/secure_memory.h"
#include "lugh/core/secure_bytes.h"

// A secret is Dannan's (dannan/identity/secure_memory.h): its bytes on locked pages, wiped
// when it goes, with no conversion to text and no stream operator, so it cannot reach a log
// line by accident. Move-only, and compared in constant time with ==. What is here is
// Lugh's use of it for what people type and read: passwords, tokens, codes.
namespace lugh {

using Secret = dannan::identity::Secret;

// What a log line or error says in a secret's place.
inline constexpr std::string_view kRedacted = "[redacted]";

// A secret from text. The text given is wiped once copied, so the caller's copy does not
// outlive this one.
inline Secret text_secret(std::string text) {
  Secret out(byte_span(text));
  dannan::identity::cleanse(std::span(reinterpret_cast<std::uint8_t*>(text.data()), text.size()));
  return out;
}

// A secret's bytes read as text, for the code that checks, hashes or shows a password, a
// token or a code. Nowhere else.
inline std::string_view secret_text(const Secret& secret) {
  const auto bytes = secret.reveal();
  return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

}  // namespace lugh
