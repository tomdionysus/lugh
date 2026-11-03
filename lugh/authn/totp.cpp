//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "authn/totp.h"

#include <openssl/crypto.h>

#include <cstdio>

#include "core/encoding.h"
#include "crypto/hmac.h"

namespace lugh::authn {

namespace {

// RFC 3986 percent-encoding of everything but the unreserved characters.
void append_escaped(std::string& out, std::string_view text) {
  static constexpr char kDigits[] = "0123456789ABCDEF";
  for (const char c : text) {
    const auto byte = static_cast<unsigned char>(c);
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~') {
      out.push_back(c);
    } else {
      out.push_back('%');
      out.push_back(kDigits[byte >> 4]);
      out.push_back(kDigits[byte & 0x0f]);
    }
  }
}

}  // namespace

std::optional<std::uint32_t> hotp(std::span<const unsigned char> secret, std::uint64_t counter, unsigned digits) {
  unsigned char message[8];
  for (int i = 7; i >= 0; --i) {
    message[i] = static_cast<unsigned char>(counter);
    counter >>= 8;
  }
  const auto mac = crypto::hmac(crypto::HmacDigest::sha1, secret, message);
  if (!mac.ok || mac.value.size() != 20) return std::nullopt;

  // RFC 4226, section 5.3: dynamic truncation.
  const auto offset = mac.value[19] & 0x0f;
  const std::uint32_t binary = (static_cast<std::uint32_t>(mac.value[offset] & 0x7f) << 24) | (static_cast<std::uint32_t>(mac.value[offset + 1]) << 16) |
                               (static_cast<std::uint32_t>(mac.value[offset + 2]) << 8) | mac.value[offset + 3];
  std::uint32_t modulus = 1;
  for (unsigned i = 0; i < digits; ++i) modulus *= 10;
  return binary % modulus;
}

std::string totp_code(std::span<const unsigned char> secret, std::uint64_t step) {
  const auto code = hotp(secret, step, kTotpDigits);
  if (!code) return {};
  char buffer[16];
  std::snprintf(buffer, sizeof buffer, "%06u", static_cast<unsigned>(*code));
  return buffer;
}

std::optional<std::uint64_t> totp_match(std::span<const unsigned char> secret, std::string_view code, std::uint64_t unix_seconds,
                                        std::optional<std::uint64_t> last_used) {
  if (code.size() != kTotpDigits) return std::nullopt;
  for (const char c : code) {
    if (c < '0' || c > '9') return std::nullopt;
  }

  const auto now = totp_step(unix_seconds);
  std::optional<std::uint64_t> matched;
  for (std::uint64_t step = now == 0 ? 0 : now - 1; step <= now + 1; ++step) {
    const auto expected = totp_code(secret, step);
    if (expected.size() != kTotpDigits) return std::nullopt;
    const bool same = CRYPTO_memcmp(expected.data(), code.data(), kTotpDigits) == 0;
    // The latest step that matches; a later step is never refused for an earlier one.
    if (same && (!last_used || step > *last_used)) matched = step;
  }
  return matched;
}

Secret otpauth_uri(std::string_view issuer, std::string_view account, std::span<const unsigned char> secret) {
  std::string out;
  out.reserve(64 + 3 * (issuer.size() * 2 + account.size()) + secret.size() * 2);
  out += "otpauth://totp/";
  append_escaped(out, issuer);
  out += ':';
  append_escaped(out, account);
  out += "?secret=";
  auto encoded = encoding::base32(secret);
  out += encoded;
  OPENSSL_cleanse(encoded.data(), encoded.size());
  out += "&issuer=";
  append_escaped(out, issuer);
  out += "&algorithm=SHA1&digits=6&period=30";
  return Secret(std::move(out));
}

}  // namespace lugh::authn
