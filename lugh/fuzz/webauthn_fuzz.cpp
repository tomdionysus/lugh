//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// What an authenticator sends, through the browser: CBOR (an attestation object, attested
// credential data and its COSE key), authenticator data, and an ES256 signature in DER. An item
// read from the front ends inside the input, and reading those bytes alone gives the same item;
// whatever decodes is offered as a COSE key. The same bytes are read as authenticator data and as
// a signature: a signature that converts is 64 bytes from a DER no longer than 72.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <span>

#include "lugh/webauthn/cbor.h"
#include "lugh/webauthn/ceremony.h"
#include "lugh/webauthn/cose.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lugh::webauthn;
  const std::span<const std::uint8_t> input(data, size);

  std::size_t used = 0;
  const auto front = cbor::decode(input, &used);
  if (front) {
    if (used == 0 || used > size) std::abort();
    const auto alone = cbor::decode(input.first(used));
    if (!alone) std::abort();
    (void)public_key(*front);
  }

  const auto whole = cbor::decode(input);
  if (whole && (!front || used != size)) std::abort();

  if (const auto authenticator = parse_authenticator_data(input)) {
    if (authenticator->credential.has_value() != bool(authenticator->flags & kAttestedData)) std::abort();
    if (authenticator->backed_up() && !authenticator->backup_eligible()) std::abort();
    if (size < 37) std::abort();
  }
  if (es256_raw_signature(input) && size > 72) std::abort();
  return 0;
}
