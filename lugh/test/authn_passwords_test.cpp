//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "authn/passwords.h"

#include <gtest/gtest.h>

#include "fakes/memory_files.h"
#include "helpers/authn_rig.h"

using lugh::byte_span;
using lugh::Fault;
using lugh::Secret;
using lugh::authn::BreachedPasswords;
using lugh::authn::Passwords;

TEST(BreachedPasswords, OneALineFoldedToLowerCase) {
  const auto list = BreachedPasswords::from_text(byte_span("# a comment\nPassword1\r\n\nletmein\nhunter2"));
  EXPECT_EQ(list.size(), 3u);
  EXPECT_TRUE(list.contains(byte_span("password1")));
  EXPECT_TRUE(list.contains(byte_span("PASSWORD1")));
  EXPECT_TRUE(list.contains(byte_span("hunter2")));
  EXPECT_FALSE(list.contains(byte_span("# a comment")));
  EXPECT_FALSE(list.contains(byte_span("")));
  EXPECT_FALSE(list.contains(byte_span("correct horse battery")));
}

TEST(BreachedPasswords, LoadedThroughFiles) {
  MemoryFiles files;
  files.put("/etc/breached", lugh::Bytes{'a', 'b', 'c', '\n'});
  const auto loaded = run(BreachedPasswords::load(files, "/etc/breached"));
  ASSERT_TRUE(loaded.ok) << loaded.error;
  EXPECT_TRUE(loaded.value.contains(byte_span("ABC")));
  const auto missing = run(BreachedPasswords::load(files, "/etc/missing"));
  ASSERT_FALSE(missing.ok);
  EXPECT_EQ(missing.error.rfind("authn.breached_passwords: ", 0), 0u);
}

namespace {

class PasswordsTest : public ::testing::Test {
 protected:
  AuthnRig rig{BreachedPasswords::from_text(byte_span("password1234\nCorrectHorseBattery"))};
  Passwords& passwords = *rig.passwords;
};

}  // namespace

TEST_F(PasswordsTest, TheRules) {
  const auto alice = rig.person("alice");
  EXPECT_TRUE(passwords.acceptable(Secret("twelve chars"), alice).ok());
  EXPECT_EQ(passwords.acceptable(Secret("eleven char"), alice).fault, Fault::invalid);
  // Twelve characters, though more bytes: counted as a person counts them.
  EXPECT_TRUE(passwords.acceptable(Secret("\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9\xc3\xa9"), alice).ok());
  EXPECT_EQ(passwords.acceptable(Secret(std::string(257, 'x')), alice).fault, Fault::invalid);
  EXPECT_EQ(passwords.acceptable(Secret("PASSWORD1234"), alice).fault, Fault::invalid);
  EXPECT_EQ(passwords.acceptable(Secret("correcthorsebattery"), alice).fault, Fault::invalid);
  EXPECT_EQ(passwords.acceptable(Secret("ALICE@example.com"), alice).fault, Fault::invalid);
}

TEST_F(PasswordsTest, ARefusalNeverSaysThePassword) {
  const auto alice = rig.person("alice");
  for (const auto* attempt : {"short", "password1234", "alice@example.com"}) {
    const auto refused = passwords.acceptable(Secret(attempt), alice);
    EXPECT_EQ(refused.message.find(attempt), std::string::npos) << refused.message;
  }
}

TEST_F(PasswordsTest, SetThenVerify) {
  const auto alice = rig.person("alice");
  EXPECT_FALSE(run(passwords.has_password(alice.id)));
  ASSERT_TRUE(run(passwords.set(rig.admin, alice, Secret("correct horse battery"))).ok());
  EXPECT_TRUE(run(passwords.has_password(alice.id)));
  EXPECT_TRUE(run(passwords.verify(alice.id, Secret("correct horse battery"))));
  EXPECT_FALSE(run(passwords.verify(alice.id, Secret("correct horse batterY"))));
  EXPECT_FALSE(run(passwords.verify("nobody", Secret("correct horse battery"))));
  EXPECT_TRUE(rig.audited("password.set"));
}

TEST_F(PasswordsTest, TheStoredRecordIsAHash) {
  const auto alice = rig.person("alice");
  run(passwords.set(rig.admin, alice, Secret("correct horse battery")));
  const auto record = rig.store->get_now(Passwords::kTable, alice.id);
  ASSERT_TRUE(record);
  const std::string value(record->value.begin(), record->value.end());
  EXPECT_EQ(value.find("correct horse battery"), std::string::npos);
}

TEST_F(PasswordsTest, AServiceHasNoPassword) {
  const auto service = run(rig.directory->create_user(rig.admin, {lugh::directory::Kind::service, "backup", "", ""})).value;
  EXPECT_EQ(run(passwords.set(rig.admin, service, Secret("correct horse battery"))).fault, Fault::refused);
}

TEST_F(PasswordsTest, AnOldHashMovesToTheCurrentCosts) {
  const auto alice = rig.person("alice");
  {
    // Set under cheaper costs, as an older release would have.
    Passwords older(rig.logger, rig.store, rig.random, rig.clock, rig.audit, test_pool(), lugh::crypto::Argon2Params{32, 1, 1}, {}, {});
    ASSERT_TRUE(run(older.set(rig.admin, alice, Secret("correct horse battery"))).ok());
  }
  const auto before = rig.store->get_now(Passwords::kTable, alice.id)->version;
  EXPECT_TRUE(run(passwords.verify(alice.id, Secret("correct horse battery"))));
  EXPECT_EQ(rig.store->get_now(Passwords::kTable, alice.id)->version, before + 1);
  // Now current: no further write.
  EXPECT_TRUE(run(passwords.verify(alice.id, Secret("correct horse battery"))));
  EXPECT_EQ(rig.store->get_now(Passwords::kTable, alice.id)->version, before + 1);
}

TEST_F(PasswordsTest, ForgottenWithTheUser) {
  const auto alice = rig.person("alice");
  run(passwords.set(rig.admin, alice, Secret("correct horse battery")));
  ASSERT_TRUE(run(rig.directory->remove_user(rig.admin, alice.id)).ok());
  EXPECT_FALSE(run(passwords.has_password(alice.id)));
  EXPECT_TRUE(rig.audited("password.remove"));
}
