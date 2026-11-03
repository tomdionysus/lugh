//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "core/secret.h"

namespace lugh::authn {

// RFC 6238 as every authenticator app does it: HMAC-SHA-1, six digits, 30-second steps.
inline constexpr std::size_t kTotpSecretBytes = 20;
inline constexpr std::uint64_t kTotpStepSeconds = 30;
inline constexpr unsigned kTotpDigits = 6;

// RFC 4226's HOTP: the code for one counter, as a number of `digits` digits. nullopt only
// when HMAC itself fails.
std::optional<std::uint32_t> hotp(std::span<const unsigned char> secret, std::uint64_t counter, unsigned digits);

// The step a time falls in.
inline std::uint64_t totp_step(std::uint64_t unix_seconds) { return unix_seconds / kTotpStepSeconds; }

// The six digits for a step, zero-padded. Empty when HMAC fails.
std::string totp_code(std::span<const unsigned char> secret, std::uint64_t step);

// The step a code was made for, if it was made for this step or one either side of it, and
// for a step after `last_used`: a code already used, or one older than it, is refused, so
// a code cannot be replayed. Every step in the window is computed and compared in constant
// time, whichever matches.
std::optional<std::uint64_t> totp_match(std::span<const unsigned char> secret, std::string_view code, std::uint64_t unix_seconds,
                                        std::optional<std::uint64_t> last_used);

// The otpauth:// URI an authenticator app reads from a QR code
// (github.com/google/google-authenticator/wiki/Key-Uri-Format). Holds the secret, so it
// is a Secret too.
Secret otpauth_uri(std::string_view issuer, std::string_view account, std::span<const unsigned char> secret);

}  // namespace lugh::authn
