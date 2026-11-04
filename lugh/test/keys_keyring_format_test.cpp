//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/keys/keyring_format.h"
#include "lugh/test/fixtures/hex.h"

using namespace lugh::keys;

namespace {

KeyringHeader credential_header() {
  KeyringHeader header;
  header.source = MasterKeySource::credential;
  header.id = repeated(0x11, kKeyringIdBytes);
  return header;
}

KeyringHeader passphrase_header() {
  KeyringHeader header;
  header.source = MasterKeySource::passphrase;
  header.id = repeated(0x22, kKeyringIdBytes);
  header.argon2 = lugh::crypto::Argon2Costs{65536, 3, 4};
  header.salt = repeated(0x33, kPassphraseSaltBytes);
  return header;
}

DataKey key(std::string name, std::uint32_t epoch, unsigned char fill) {
  DataKey out;
  out.name = std::move(name);
  out.epoch = epoch;
  out.key = lugh::SecureBuffer(kDataKeyBytes, fill);
  return out;
}

lugh::Bytes plain(const lugh::SecureBuffer& secure) { return lugh::Bytes(secure.begin(), secure.end()); }

}  // namespace

TEST(KeyringFormat, KeyNames) {
  EXPECT_TRUE(valid_key_name("users"));
  EXPECT_TRUE(valid_key_name("app_access2"));
  EXPECT_TRUE(valid_key_name(std::string(64, 'a')));
  EXPECT_FALSE(valid_key_name(""));
  EXPECT_FALSE(valid_key_name(std::string(65, 'a')));
  EXPECT_FALSE(valid_key_name("Users"));
  EXPECT_FALSE(valid_key_name("a-b"));
  EXPECT_FALSE(valid_key_name("a b"));
  EXPECT_FALSE(valid_key_name(std::string("a\0b", 3)));
}

TEST(KeyringFormat, ACredentialHeader) {
  const auto bytes = encode_header(credential_header());
  EXPECT_EQ(to_hex(bytes), to_hex(lugh::byte_span("LUGHKEYS")) + "0101" + std::string(32, '1'));

  const auto parsed = decode_header(bytes);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->length, bytes.size());
  EXPECT_EQ(parsed->header.source, MasterKeySource::credential);
  EXPECT_EQ(parsed->header.id, repeated(0x11, kKeyringIdBytes));
}

TEST(KeyringFormat, APassphraseHeader) {
  auto bytes = encode_header(passphrase_header());
  EXPECT_EQ(bytes.size(), 8u + 1 + 1 + 16 + 12 + 16);

  // The sealed body follows; the parse says where it starts.
  bytes.push_back(0xff);
  const auto parsed = decode_header(bytes);
  ASSERT_TRUE(parsed);
  EXPECT_EQ(parsed->length, bytes.size() - 1);
  EXPECT_EQ(parsed->header.source, MasterKeySource::passphrase);
  EXPECT_EQ(parsed->header.argon2.memory_kib, 65536u);
  EXPECT_EQ(parsed->header.argon2.iterations, 3u);
  EXPECT_EQ(parsed->header.argon2.lanes, 4u);
  EXPECT_EQ(parsed->header.salt, repeated(0x33, kPassphraseSaltBytes));
}

TEST(KeyringFormat, RefusesHeadersThatAreNot) {
  const auto good = encode_header(passphrase_header());

  EXPECT_FALSE(decode_header({}));
  for (std::size_t length = 0; length < good.size(); ++length) EXPECT_FALSE(decode_header(std::span(good).first(length))) << length;

  auto magic = good;
  magic[0] = 'X';
  EXPECT_FALSE(decode_header(magic));

  auto version = good;
  version[8] = 2;
  EXPECT_FALSE(decode_header(version));

  for (const int source : {0, 3, 255}) {
    auto other = good;
    other[9] = static_cast<unsigned char>(source);
    EXPECT_FALSE(decode_header(other)) << source;
  }

  // Costs that would take a terabyte, or that Argon2 cannot have.
  auto memory = good;
  memory[26] = 0xff;
  EXPECT_FALSE(decode_header(memory));
  auto passes = good;
  std::fill(passes.begin() + 30, passes.begin() + 34, 0);
  EXPECT_FALSE(decode_header(passes));

  EXPECT_FALSE(decode_header(lugh::Bytes(kMostKeyringBytes + 1, 0)));
}

TEST(KeyringFormat, ABody) {
  const std::vector<DataKey> keys{key("users", 1, 0xaa), key("users", 2, 0xbb), key("audit", 1, 0xcc)};
  const auto body = encode_body(keys);

  const auto parsed = decode_body(body);
  ASSERT_TRUE(parsed);
  ASSERT_EQ(parsed->size(), 3u);
  EXPECT_EQ((*parsed)[1].name, "users");
  EXPECT_EQ((*parsed)[1].epoch, 2u);
  EXPECT_EQ(plain((*parsed)[1].key), repeated(0xbb, 32));
  EXPECT_EQ((*parsed)[2].name, "audit");
}

TEST(KeyringFormat, AnEmptyBody) {
  const auto parsed = decode_body(encode_body({}));
  ASSERT_TRUE(parsed);
  EXPECT_TRUE(parsed->empty());
}

TEST(KeyringFormat, RefusesBodiesThatAreNot) {
  const auto good = plain(encode_body({key("users", 1, 0xaa)}));
  // count 4 | name length 1 | "users" 5 | epoch 4 | key length 1 | key 32

  EXPECT_FALSE(decode_body({}));
  for (std::size_t length = 0; length < good.size(); ++length) EXPECT_FALSE(decode_body(std::span(good).first(length))) << length;

  auto trailing = good;
  trailing.push_back(0);
  EXPECT_FALSE(decode_body(trailing));

  auto more = good;
  more[3] = 2;
  EXPECT_FALSE(decode_body(more));

  auto too_many = good;
  too_many[1] = 0xff;
  EXPECT_FALSE(decode_body(too_many));

  auto bad_name = good;
  bad_name[5] = 'U';
  EXPECT_FALSE(decode_body(bad_name));

  auto empty_name = plain(encode_body({key("users", 1, 0xaa)}));
  empty_name[4] = 0;
  EXPECT_FALSE(decode_body(empty_name));

  auto epoch_zero = good;
  std::fill(epoch_zero.begin() + 10, epoch_zero.begin() + 14, 0);
  EXPECT_FALSE(decode_body(epoch_zero));

  auto short_key = good;
  short_key[14] = 31;
  EXPECT_FALSE(decode_body(short_key));

  EXPECT_FALSE(decode_body(encode_body({key("users", 1, 0xaa), key("users", 1, 0xbb)})));
}
