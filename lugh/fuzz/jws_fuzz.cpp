//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// What arrives as a token or a key: a compact JWS (a bearer token, a client's signed JWT, a
// DPoP proof) and a JWK (a client's registered keys). The first byte picks which. A JWS
// that parses is verified against a fixed key, and a JWK that parses must make the same JWK
// again.

#include <boost/json.hpp>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "lugh/tokens/jose.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::tokens;
  if (size == 0) return 0;
  const std::string_view text(reinterpret_cast<const char*>(data + 1), size - 1);
  static const auto key = SigningKey::generate(SigningAlgorithm::es256);
  static const std::vector<VerifyKey> keys{{"k", SigningAlgorithm::es256, key.public_key()}};

  if (data[0] % 2 == 0) {
    if (const auto jws = jws_parse(text)) (void)jws_verify(*jws, keys);
    return 0;
  }
  boost::system::error_code ec;
  const auto parsed = boost::json::parse(text, ec);
  if (ec || !parsed.is_object()) return 0;
  if (const auto jwk = from_jwk(parsed.as_object())) {
    const auto again = public_jwk(*jwk);
    if (!again) __builtin_trap();
    const auto back = from_jwk(*again);
    if (!back || back->public_key != jwk->public_key) __builtin_trap();
  }
  return 0;
}
