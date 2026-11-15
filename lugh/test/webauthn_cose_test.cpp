//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <variant>

#include "dannan/identity/signing.h"
#include "lugh/webauthn/cose.h"

using lugh::webauthn::public_key;
using lugh::webauthn::PublicKey;
namespace cbor = lugh::webauthn::cbor;

namespace {

// Enough CBOR writing to build COSE keys: a map of integer labels to integers or bytes.
struct Entry {
  std::int64_t label;
  std::variant<std::int64_t, std::string, std::vector<std::int64_t>> value;
};

void head(std::string& out, std::uint8_t major, std::uint64_t n) {
  const auto initial = static_cast<char>(major << 5);
  if (n < 24) {
    out.push_back(static_cast<char>(initial | static_cast<char>(n)));
  } else if (n <= 0xff) {
    out.push_back(static_cast<char>(initial | 24));
    out.push_back(static_cast<char>(n));
  } else {
    out.push_back(static_cast<char>(initial | 25));
    out.push_back(static_cast<char>(n >> 8));
    out.push_back(static_cast<char>(n & 0xff));
  }
}

void integer(std::string& out, std::int64_t n) {
  if (n >= 0) {
    head(out, 0, static_cast<std::uint64_t>(n));
  } else {
    head(out, 1, static_cast<std::uint64_t>(-1 - n));
  }
}

std::optional<cbor::Value> cose(const std::vector<Entry>& entries) {
  std::string out;
  head(out, 5, entries.size());
  for (const auto& [label, value] : entries) {
    integer(out, label);
    if (const auto* n = std::get_if<std::int64_t>(&value)) {
      integer(out, *n);
    } else if (const auto* bytes = std::get_if<std::string>(&value)) {
      head(out, 2, bytes->size());
      out += *bytes;
    } else {
      const auto& list = std::get<std::vector<std::int64_t>>(value);
      head(out, 4, list.size());
      for (const auto each : list) integer(out, each);
    }
  }
  return cbor::decode({reinterpret_cast<const std::uint8_t*>(out.data()), out.size()});
}

std::optional<PublicKey> key_of(const std::vector<Entry>& entries) {
  const auto value = cose(entries);
  if (!value) return std::nullopt;
  return public_key(*value);
}

// A fresh key's raw coordinates, cut from its SubjectPublicKeyInfo.
struct Raw {
  std::string x, y;
  lugh::Bytes der;
};

Raw p256() {
  const auto key = dannan::identity::SigningKey::generate(dannan::identity::SigningAlgorithm::es256);
  const auto der = key.public_key();
  const std::string all(der.begin(), der.end());
  // The point is the last 65 bytes: 0x04, x, y.
  return {all.substr(all.size() - 64, 32), all.substr(all.size() - 32), der};
}

Raw ed25519() {
  const auto key = dannan::identity::SigningKey::generate(dannan::identity::SigningAlgorithm::ed25519);
  const auto der = key.public_key();
  const std::string all(der.begin(), der.end());
  return {all.substr(all.size() - 32), {}, der};
}

}  // namespace

TEST(Cose, AnEs256Key) {
  const auto raw = p256();
  const auto key = key_of({{1, 2}, {3, -7}, {-1, 1}, {-2, raw.x}, {-3, raw.y}});
  ASSERT_TRUE(key);
  EXPECT_EQ(key->kind, PublicKey::Kind::es256);
  EXPECT_EQ(key->algorithm(), -7);
  EXPECT_EQ(key->der, raw.der) << "the same SubjectPublicKeyInfo Dannan made";
}

TEST(Cose, AnEdDsaKey) {
  const auto raw = ed25519();
  const auto key = key_of({{1, 1}, {3, -8}, {-1, 6}, {-2, raw.x}});
  ASSERT_TRUE(key);
  EXPECT_EQ(key->kind, PublicKey::Kind::eddsa);
  EXPECT_EQ(key->der, raw.der);
}

// RS256's numbers are carried, not judged: Dannan's verify_rs256 judges the modulus's size.
TEST(Cose, AnRs256Key) {
  const std::string n(256, '\xc5');
  const std::string e("\x01\x00\x01", 3);
  const auto key = key_of({{1, 3}, {3, -257}, {-1, n}, {-2, e}});
  ASSERT_TRUE(key);
  EXPECT_EQ(key->kind, PublicKey::Kind::rs256);
  EXPECT_EQ(key->algorithm(), -257);
  EXPECT_EQ(key->modulus, n);
  EXPECT_EQ(key->exponent, e);
  EXPECT_FALSE(key_of({{1, 3}, {3, -257}, {-1, n}, {-2, std::string()}})) << "an empty exponent";
  EXPECT_FALSE(key_of({{1, 3}, {3, -257}, {-1, n}})) << "no exponent";
}

TEST(Cose, AnAlgorithmThatDoesNotFitItsKeyIsRefused) {
  const auto raw = p256();
  EXPECT_FALSE(key_of({{1, 2}, {3, -35}, {-1, 2}, {-2, raw.x}, {-3, raw.y}})) << "ES384";
  EXPECT_FALSE(key_of({{1, 2}, {3, -8}, {-1, 1}, {-2, raw.x}, {-3, raw.y}})) << "EdDSA on P-256";
  EXPECT_FALSE(key_of({{1, 2}, {3, -7}, {-1, 6}, {-2, raw.x}, {-3, raw.y}})) << "ES256 on Ed25519";
  EXPECT_FALSE(key_of({{1, 2}, {-1, 1}, {-2, raw.x}, {-3, raw.y}})) << "no alg";
  EXPECT_FALSE(key_of({{1, 4}, {3, -7}, {-1, 1}, {-2, raw.x}, {-3, raw.y}})) << "a symmetric key type";
  const auto ed = ed25519();
  EXPECT_FALSE(key_of({{1, 1}, {3, -7}, {-1, 6}, {-2, ed.x}})) << "ES256 on an OKP key";
}

TEST(Cose, APrivatePartIsRefused) {
  const auto raw = p256();
  EXPECT_FALSE(key_of({{1, 2}, {3, -7}, {-1, 1}, {-2, raw.x}, {-3, raw.y}, {-4, std::string(32, 'd')}}));
  const auto ed = ed25519();
  EXPECT_FALSE(key_of({{1, 1}, {3, -8}, {-1, 6}, {-2, ed.x}, {-4, std::string(32, 'd')}}));
  const std::string n(256, '\xc5');
  EXPECT_FALSE(key_of({{1, 3}, {3, -257}, {-1, n}, {-2, std::string("\x01\x00\x01", 3)}, {-3, std::string(256, 'd')}})) << "RSA's d";
  EXPECT_FALSE(key_of({{1, 3}, {3, -257}, {-1, n}, {-2, std::string("\x01\x00\x01", 3)}, {-12, std::string(8, 'p')}})) << "RSA's other primes";
}

TEST(Cose, KeyOpsMustAllowVerifying) {
  const auto raw = p256();
  EXPECT_TRUE(key_of({{1, 2}, {3, -7}, {4, std::vector<std::int64_t>{2}}, {-1, 1}, {-2, raw.x}, {-3, raw.y}}));
  EXPECT_FALSE(key_of({{1, 2}, {3, -7}, {4, std::vector<std::int64_t>{1}}, {-1, 1}, {-2, raw.x}, {-3, raw.y}})) << "sign only";
  EXPECT_FALSE(key_of({{1, 2}, {3, -7}, {4, std::int64_t{2}}, {-1, 1}, {-2, raw.x}, {-3, raw.y}})) << "not an array";
}

TEST(Cose, CoordinatesOfTheWrongLengthOrOffTheCurveAreRefused) {
  const auto raw = p256();
  EXPECT_FALSE(key_of({{1, 2}, {3, -7}, {-1, 1}, {-2, raw.x.substr(1)}, {-3, raw.y}}));
  EXPECT_FALSE(key_of({{1, 2}, {3, -7}, {-1, 1}, {-2, raw.x}})) << "no y";
  EXPECT_FALSE(key_of({{1, 2}, {3, -7}, {-1, 1}, {-2, std::string(32, '\x01')}, {-3, std::string(32, '\x01')}})) << "not a point on P-256";
  EXPECT_FALSE(key_of({{1, 2}, {3, -7}, {-1, 1}, {-2, raw.x}, {-3, std::int64_t{1}}})) << "y not bytes";
  const auto ed = ed25519();
  EXPECT_FALSE(key_of({{1, 1}, {3, -8}, {-1, 6}, {-2, ed.x + "x"}}));
  EXPECT_FALSE(key_of({{1, 1}, {3, -8}, {-1, 6}, {-2, ed.x}, {-3, ed.x}})) << "a y on an OKP key";
}

TEST(Cose, OnlyAMapIsAKey) {
  const auto array = cbor::decode(std::vector<std::uint8_t>{0x80});
  ASSERT_TRUE(array);
  EXPECT_FALSE(public_key(*array));
}
