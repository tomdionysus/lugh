//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// What lugh_client reads from outside the process: a JWKS and a discovery document from the
// network, and a token from whoever presents one. The first byte picks which. A JWKS goes to
// Verifier::set_keys (refusing is fine, crashing is not), a token to verify_access and verify_id
// against keys that include fuzzed ones, a discovery document to Endpoints::from_discovery.

#include <boost/json.hpp>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "dannan/contract/time_source.h"
#include "lugh/client/oauth_client.h"
#include "lugh/client/testing.h"
#include "lugh/client/verifier.h"

namespace {

constexpr const char* kIssuer = "https://lugh.example";

class FixedWall final : public dannan::contract::WallClock {
 public:
  std::uint64_t unix_ms() const noexcept override { return 1'800'000'000'000ull; }
};

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::client;
  if (size == 0) return 0;
  const std::string_view text(reinterpret_cast<const char*>(data + 1), size - 1);
  static const FixedWall wall;
  static const auto key = dannan::identity::SigningKey::generate(dannan::identity::SigningAlgorithm::es256);
  static Verifier verifier({kIssuer}, wall);
  static const bool keyed = (verifier.set_keys(kIssuer, testing::jwks(key, "k1")), true);
  (void)keyed;

  switch (data[0] % 3) {
    case 0: {
      boost::system::error_code ec;
      const auto parsed = boost::json::parse(text, ec);
      if (ec || !parsed.is_object()) return 0;
      try {
        (void)verifier.set_keys(kIssuer, parsed.as_object());
      } catch (const std::runtime_error&) {
        // A document that is no JWKS is refused.
      }
      // Keys from the fuzzed document, or the real one, then a token under the real key.
      (void)verifier.verify_access(
          testing::sign_access_token(key, "k1", {{"iss", kIssuer}, {"sub", "u"}, {"client_id", "c"}, {"jti", "j"}, {"exp", 1'800'000'060}}));
      verifier.set_keys(kIssuer, testing::jwks(key, "k1"));
      return 0;
    }
    case 1:
      (void)verifier.verify_access(text, "lir");
      (void)verifier.verify_id(text, "app1", "n");
      return 0;
    default: {
      boost::system::error_code ec;
      const auto parsed = boost::json::parse(text, ec);
      if (ec || !parsed.is_object()) return 0;
      (void)Endpoints::from_discovery(parsed.as_object(), kIssuer);
      return 0;
    }
  }
}
