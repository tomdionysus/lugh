#include "keys/keyring.h"

#include <gtest/gtest.h>

#include "fakes/fixed_random.h"
#include "helpers/hex.h"

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

lugh::Bytes plain(const lugh::SecureBytes& secure) { return lugh::Bytes(secure.begin(), secure.end()); }

}  // namespace

TEST(Keyring, ANewKeyringIsEmpty) {
  const auto keyring = made();
  EXPECT_EQ(keyring.size(), 0u);
  EXPECT_EQ(keyring.current("users"), nullptr);
  EXPECT_EQ(keyring.id_hex(), std::string(32, '1'));
}

TEST(Keyring, SealThenOpen) {
  FixedRandom random;
  auto keyring = made();
  ASSERT_TRUE(keyring.rotate("users", random).ok);
  ASSERT_TRUE(keyring.rotate("audit", random).ok);

  const auto file = keyring.seal(random);
  ASSERT_TRUE(file.ok) << file.error;

  const auto opened = Keyring::open(file.value, kMaster);
  ASSERT_TRUE(opened.ok) << opened.error;
  EXPECT_EQ(opened.value.size(), 2u);
  EXPECT_EQ(opened.value.id_hex(), keyring.id_hex());
  ASSERT_NE(opened.value.current("users"), nullptr);
  EXPECT_EQ(plain(opened.value.current("users")->key), plain(keyring.current("users")->key));
}

TEST(Keyring, TheKeysAreNotInTheFile) {
  FixedRandom random;
  auto keyring = made();
  ASSERT_TRUE(keyring.rotate("users", random).ok);
  const auto file = keyring.seal(random).value;
  const auto key = plain(keyring.current("users")->key);
  EXPECT_EQ(std::search(file.begin(), file.end(), key.begin(), key.end()), file.end());
}

TEST(Keyring, TheWrongMasterKeyOpensNothing) {
  FixedRandom random;
  const auto file = made().seal(random).value;

  auto wrong = kMaster;
  wrong[31] ^= 1;
  const auto opened = Keyring::open(file, wrong);
  EXPECT_FALSE(opened.ok);
  EXPECT_NE(opened.error.find("wrong key"), std::string::npos);

  EXPECT_FALSE(Keyring::open(file, repeated(0x5a, 31)).ok);
  EXPECT_FALSE(Keyring::create(header(), repeated(0x5a, 16)).ok);
}

TEST(Keyring, AnyEditIsRefused) {
  FixedRandom random;
  auto keyring = made();
  ASSERT_TRUE(keyring.rotate("users", random).ok);
  const auto file = keyring.seal(random).value;

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
  FixedRandom random;
  const auto first = made().seal(random).value;
  auto second = Keyring::create(header(0x99), kMaster).value.seal(random).value;

  const auto header_length = encode_header(header()).size();
  lugh::Bytes spliced(second.begin(), second.begin() + header_length);
  spliced.insert(spliced.end(), first.begin() + header_length, first.end());
  EXPECT_FALSE(Keyring::open(spliced, kMaster).ok);
}

TEST(Keyring, EachSealIsFresh) {
  FixedRandom random;
  const auto keyring = made();
  const auto a = keyring.seal(random).value;
  const auto b = keyring.seal(random).value;
  EXPECT_NE(a, b);
  EXPECT_TRUE(Keyring::open(a, kMaster).ok);
  EXPECT_TRUE(Keyring::open(b, kMaster).ok);
}

TEST(Keyring, RotationAddsAnEpoch) {
  FixedRandom random;
  auto keyring = made();

  EXPECT_EQ(keyring.rotate("users", random).value, 1u);
  const auto first = plain(keyring.current("users")->key);
  EXPECT_EQ(keyring.rotate("users", random).value, 2u);
  EXPECT_EQ(keyring.rotate("audit", random).value, 1u);

  EXPECT_EQ(keyring.current("users")->epoch, 2u);
  EXPECT_NE(plain(keyring.current("users")->key), first);
  ASSERT_NE(keyring.find("users", 1), nullptr);
  EXPECT_EQ(plain(keyring.find("users", 1)->key), first);
  EXPECT_EQ(keyring.find("users", 3), nullptr);
  EXPECT_EQ(keyring.size(), 3u);
}

TEST(Keyring, RotationRefusesBadNamesAndBadRandomness) {
  FixedRandom random;
  auto keyring = made();
  EXPECT_FALSE(keyring.rotate("Users", random).ok);
  EXPECT_FALSE(keyring.rotate("", random).ok);

  random.fail = true;
  EXPECT_FALSE(keyring.rotate("users", random).ok);
  EXPECT_EQ(keyring.size(), 0u);
}

TEST(Keyring, AddTakesAKeyMadeElsewhere) {
  auto keyring = made();
  DataKey key{"users", 7, lugh::SecureBytes(kDataKeyBytes, 0x42)};
  ASSERT_TRUE(keyring.add(key).ok);
  EXPECT_EQ(keyring.current("users")->epoch, 7u);

  EXPECT_FALSE(keyring.add(key).ok);
  EXPECT_FALSE(keyring.add(DataKey{"users", 0, lugh::SecureBytes(kDataKeyBytes, 1)}).ok);
  EXPECT_FALSE(keyring.add(DataKey{"users", 8, lugh::SecureBytes(16, 1)}).ok);
  EXPECT_FALSE(keyring.add(DataKey{"Users", 8, lugh::SecureBytes(kDataKeyBytes, 1)}).ok);
  EXPECT_EQ(keyring.size(), 1u);
}

TEST(Keyring, RekeyMovesToANewMasterKey) {
  FixedRandom random;
  auto keyring = made();
  ASSERT_TRUE(keyring.rotate("users", random).ok);
  const auto key = plain(keyring.current("users")->key);

  const auto next = repeated(0x77, kMasterKeyBytes);
  ASSERT_TRUE(keyring.rekey(header(0x12), next).ok);
  const auto file = keyring.seal(random).value;

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

TEST(Keyring, AnEmptyKeyringSealsNothing) {
  FixedRandom random;
  EXPECT_FALSE(Keyring().seal(random).ok);
}
