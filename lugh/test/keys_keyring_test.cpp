//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/keys/keyring.h"
#include "lugh/test/fixtures/hex.h"

using namespace lugh::keys;

namespace {

const lugh::Bytes kMaster = repeated(0x5a, kMasterKeyBytes);

KeyringHeader header(unsigned char id = 0x11) {
  KeyringHeader out;
  out.id = repeated(id, kKeyringIdBytes);
  return out;
}

Keyring made() {
  auto keyring = Keyring::create(header(), kMaster);
  EXPECT_TRUE(keyring.ok) << keyring.error;
  return std::move(keyring.value);
}

lugh::Bytes plain(const lugh::SecureBuffer& secure) { return lugh::Bytes(secure.begin(), secure.end()); }

}  // namespace

TEST(Keyring, ANewKeyringIsEmpty) {
  const auto keyring = made();
  EXPECT_EQ(keyring.size(), 0u);
  EXPECT_EQ(keyring.current("users"), nullptr);
  EXPECT_EQ(keyring.id_hex(), std::string(32, '1'));
}

TEST(Keyring, SealThenOpen) {
  auto keyring = made();
  ASSERT_TRUE(keyring.rotate("users").ok);
  ASSERT_TRUE(keyring.rotate("audit").ok);

  const auto file = keyring.seal();
  ASSERT_TRUE(file.ok) << file.error;

  const auto opened = Keyring::open(file.value, kMaster);
  ASSERT_TRUE(opened.ok) << opened.error;
  EXPECT_EQ(opened.value.size(), 2u);
  EXPECT_EQ(opened.value.id_hex(), keyring.id_hex());
  ASSERT_NE(opened.value.current("users"), nullptr);
  EXPECT_EQ(plain(opened.value.current("users")->key), plain(keyring.current("users")->key));
}

TEST(Keyring, TheKeysAreNotInTheFile) {
  auto keyring = made();
  ASSERT_TRUE(keyring.rotate("users").ok);
  const auto file = keyring.seal().value;
  const auto key = plain(keyring.current("users")->key);
  EXPECT_EQ(std::search(file.begin(), file.end(), key.begin(), key.end()), file.end());
}

TEST(Keyring, TheWrongMasterKeyOpensNothing) {
  const auto file = made().seal().value;

  auto wrong = kMaster;
  wrong[31] ^= 1;
  const auto opened = Keyring::open(file, wrong);
  EXPECT_FALSE(opened.ok);
  EXPECT_NE(opened.error.find("wrong key"), std::string::npos);

  EXPECT_FALSE(Keyring::open(file, repeated(0x5a, 31)).ok);
  EXPECT_FALSE(Keyring::create(header(), repeated(0x5a, 16)).ok);
}

TEST(Keyring, AnyEditIsRefused) {
  auto keyring = made();
  ASSERT_TRUE(keyring.rotate("users").ok);
  const auto file = keyring.seal().value;

  for (std::size_t i = 0; i < file.size(); ++i) {
    auto edited = file;
    edited[i] ^= 0x01;
    EXPECT_FALSE(Keyring::open(edited, kMaster).ok) << "byte " << i;
  }
  for (std::size_t length = 0; length < file.size(); ++length) {
    EXPECT_FALSE(Keyring::open(std::span(file).first(length), kMaster).ok) << "length " << length;
  }
}

// The header is bound into the seal: a keyring's body moved under another header (another
// id, so another KEK salt) does not open.
TEST(Keyring, ABodyCannotMoveToAnotherHeader) {
  const auto first = made().seal().value;
  auto second = Keyring::create(header(0x99), kMaster).value.seal().value;

  const auto header_length = encode_header(header()).size();
  lugh::Bytes spliced(second.begin(), second.begin() + header_length);
  spliced.insert(spliced.end(), first.begin() + header_length, first.end());
  EXPECT_FALSE(Keyring::open(spliced, kMaster).ok);
}

TEST(Keyring, EachSealIsFresh) {
  const auto keyring = made();
  const auto a = keyring.seal().value;
  const auto b = keyring.seal().value;
  EXPECT_NE(a, b);
  EXPECT_TRUE(Keyring::open(a, kMaster).ok);
  EXPECT_TRUE(Keyring::open(b, kMaster).ok);
}

TEST(Keyring, RotationAddsAnEpoch) {
  auto keyring = made();

  EXPECT_EQ(keyring.rotate("users").value, 1u);
  const auto first = plain(keyring.current("users")->key);
  EXPECT_EQ(keyring.rotate("users").value, 2u);
  EXPECT_EQ(keyring.rotate("audit").value, 1u);

  EXPECT_EQ(keyring.current("users")->epoch, 2u);
  EXPECT_NE(plain(keyring.current("users")->key), first);
  ASSERT_NE(keyring.find("users", 1), nullptr);
  EXPECT_EQ(plain(keyring.find("users", 1)->key), first);
  EXPECT_EQ(keyring.find("users", 3), nullptr);
  EXPECT_EQ(keyring.size(), 3u);
}

TEST(Keyring, RotationRefusesBadNames) {
  auto keyring = made();
  EXPECT_FALSE(keyring.rotate("Users").ok);
  EXPECT_FALSE(keyring.rotate("").ok);
  EXPECT_EQ(keyring.size(), 0u);
}

TEST(Keyring, AddTakesAKeyMadeElsewhere) {
  auto keyring = made();
  DataKey key{"users", 7, lugh::SecureBuffer(kDataKeyBytes, 0x42)};
  ASSERT_TRUE(keyring.add(key).ok);
  EXPECT_EQ(keyring.current("users")->epoch, 7u);

  EXPECT_FALSE(keyring.add(key).ok);
  EXPECT_FALSE(keyring.add(DataKey{"users", 0, lugh::SecureBuffer(kDataKeyBytes, 1)}).ok);
  EXPECT_FALSE(keyring.add(DataKey{"users", 8, lugh::SecureBuffer(16, 1)}).ok);
  EXPECT_FALSE(keyring.add(DataKey{"Users", 8, lugh::SecureBuffer(kDataKeyBytes, 1)}).ok);
  EXPECT_EQ(keyring.size(), 1u);
}

TEST(Keyring, RekeyMovesToANewMasterKey) {
  auto keyring = made();
  ASSERT_TRUE(keyring.rotate("users").ok);
  const auto key = plain(keyring.current("users")->key);

  const auto next = repeated(0x77, kMasterKeyBytes);
  ASSERT_TRUE(keyring.rekey(header(0x12), next).ok);
  const auto file = keyring.seal().value;

  EXPECT_FALSE(Keyring::open(file, kMaster).ok);
  const auto opened = Keyring::open(file, next);
  ASSERT_TRUE(opened.ok) << opened.error;
  EXPECT_EQ(plain(opened.value.current("users")->key), key);
}

TEST(Keyring, RefusesBadHeaders) {
  auto short_id = header();
  short_id.id.pop_back();
  EXPECT_FALSE(Keyring::create(short_id, kMaster).ok);

  KeyringHeader passphrase = header();
  passphrase.source = MasterKeySource::passphrase;
  passphrase.salt = repeated(1, 15);
  EXPECT_FALSE(Keyring::create(passphrase, kMaster).ok);

  passphrase.salt = repeated(1, kPassphraseSaltBytes);
  passphrase.argon2.iterations = 0;
  EXPECT_FALSE(Keyring::create(passphrase, kMaster).ok);
}

TEST(Keyring, AnEmptyKeyringSealsNothing) { EXPECT_FALSE(Keyring().seal().ok); }
