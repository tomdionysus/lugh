//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/keys/keyring_manager.h"
#include "lugh/test/fixtures/fixed_random.h"
#include "lugh/test/fixtures/hex.h"
#include "lugh/test/fixtures/logger_mock.h"
#include "lugh/test/fixtures/map_environment.h"
#include "lugh/test/fixtures/memory_files.h"
#include "lugh/test/fixtures/pools.h"
#include "lugh/test/fixtures/run.h"
#include "lugh/test/fixtures/scripted_console.h"

using namespace lugh::keys;

namespace {

const lugh::crypto::Argon2Costs kCheap{64, 1, 1};
const std::string kPassphrase = "correct horse battery staple";

class KeyringManagerTest : public ::testing::Test {
 protected:
  KeyringManager manager() { return KeyringManager(logger, files, random, console, environment, "/var/lib/lugh", test_pool()); }

  // A keyring made for a credential, saved, and the credential where systemd puts it.
  lugh::SecureBuffer initialise() {
    auto keys = manager();
    auto created = run(keys.create_for_credential());
    EXPECT_TRUE(created.ok) << created.error;
    EXPECT_TRUE(run(keys.save_new(created.value.keyring)).ok);
    files->put("/run/credentials/lugh.service/lugh-master-key", lugh::Bytes(created.value.master_key.begin(), created.value.master_key.end()));
    environment->set("CREDENTIALS_DIRECTORY", "/run/credentials/lugh.service");
    return created.value.master_key;
  }

  std::shared_ptr<MockLogger> logger = std::make_shared<MockLogger>();
  std::shared_ptr<MemoryFiles> files = std::make_shared<MemoryFiles>();
  std::shared_ptr<FixedRandom> random = std::make_shared<FixedRandom>();
  std::shared_ptr<ScriptedConsole> console = std::make_shared<ScriptedConsole>();
  std::shared_ptr<MapEnvironment> environment = std::make_shared<MapEnvironment>();
};

}  // namespace

TEST_F(KeyringManagerTest, TheKeyringLivesInTheStateDirectory) { EXPECT_EQ(manager().path(), "/var/lib/lugh/keyring"); }

TEST_F(KeyringManagerTest, InitMakesAKeyButSavesNothingUntilAsked) {
  auto keys = manager();
  const auto created = run(keys.create_for_credential());
  ASSERT_TRUE(created.ok) << created.error;
  EXPECT_EQ(created.value.master_key.size(), kMasterKeyBytes);
  EXPECT_EQ(created.value.keyring.header().source, MasterKeySource::credential);
  EXPECT_FALSE(run(files->exists("/var/lib/lugh/keyring")));

  ASSERT_TRUE(run(keys.save_new(created.value.keyring)).ok);
  EXPECT_TRUE(run(files->exists("/var/lib/lugh/keyring")));
  EXPECT_NE(logger->text().find(created.value.keyring.id_hex()), std::string::npos);
}

TEST_F(KeyringManagerTest, OpensWithTheCredential) {
  initialise();
  const auto opened = run(manager().open());
  ASSERT_TRUE(opened.ok) << opened.error;
  EXPECT_EQ(opened.value.size(), 0u);
  EXPECT_NE(logger->text().find("Opened keyring"), std::string::npos);
}

TEST_F(KeyringManagerTest, TheMasterKeyIsNeverLogged) {
  const auto key = initialise();
  ASSERT_TRUE(run(manager().open()).ok);
  const auto text = logger->text();
  EXPECT_EQ(text.find(to_hex(key)), std::string::npos);
  EXPECT_EQ(text.find(std::string(key.begin(), key.end())), std::string::npos);
}

TEST_F(KeyringManagerTest, InitNeverReplacesAKeyring) {
  initialise();
  const auto before = files->get("/var/lib/lugh/keyring");

  auto keys = manager();
  const auto again = run(keys.create_for_credential());
  EXPECT_FALSE(again.ok);
  EXPECT_NE(again.error.find("never replaced"), std::string::npos);

  console->type(kPassphrase);
  console->type(kPassphrase);
  EXPECT_FALSE(run(keys.create_with_passphrase(kCheap)).ok);
  EXPECT_TRUE(console->prompts.empty());

  EXPECT_EQ(files->get("/var/lib/lugh/keyring"), before);
}

TEST_F(KeyringManagerTest, SaveNewRefusesToReplace) {
  initialise();
  auto keys = manager();
  auto other = Keyring::create(KeyringHeader{MasterKeySource::credential, repeated(1, kKeyringIdBytes), {}, {}}, repeated(2, kMasterKeyBytes));
  EXPECT_FALSE(run(keys.save_new(other.value)).ok);
}

TEST_F(KeyringManagerTest, NoKeyringSaysToRunInit) {
  const auto opened = run(manager().open());
  EXPECT_FALSE(opened.ok);
  EXPECT_NE(opened.error.find("lugh-node init"), std::string::npos);
}

TEST_F(KeyringManagerTest, NotAKeyring) {
  files->put("/var/lib/lugh/keyring", lugh::Bytes{'n', 'o', 'p', 'e'});
  const auto opened = run(manager().open());
  EXPECT_FALSE(opened.ok);
  EXPECT_NE(opened.error.find("is not a Lugh keyring"), std::string::npos);
}

TEST_F(KeyringManagerTest, NoCredentialsDirectory) {
  initialise();
  environment = std::make_shared<MapEnvironment>();
  const auto opened = run(manager().open());
  EXPECT_FALSE(opened.ok);
  EXPECT_NE(opened.error.find("CREDENTIALS_DIRECTORY"), std::string::npos);
  EXPECT_NE(opened.error.find("lugh-master-key"), std::string::npos);
}

TEST_F(KeyringManagerTest, NoCredential) {
  initialise();
  environment->set("CREDENTIALS_DIRECTORY", "/run/credentials/other");
  const auto opened = run(manager().open());
  EXPECT_FALSE(opened.ok);
  EXPECT_NE(opened.error.find("no credential lugh-master-key"), std::string::npos);
}

TEST_F(KeyringManagerTest, ACredentialOfTheWrongLength) {
  initialise();
  files->put("/run/credentials/lugh.service/lugh-master-key", repeated(1, 33));
  const auto opened = run(manager().open());
  EXPECT_FALSE(opened.ok);
  EXPECT_NE(opened.error.find("33 bytes"), std::string::npos);
}

TEST_F(KeyringManagerTest, TheWrongCredential) {
  initialise();
  files->put("/run/credentials/lugh.service/lugh-master-key", repeated(1, kMasterKeyBytes));
  const auto opened = run(manager().open());
  EXPECT_FALSE(opened.ok);
  EXPECT_NE(opened.error.find("does not open"), std::string::npos);
}

TEST_F(KeyringManagerTest, APassphraseKeyring) {
  console->type(kPassphrase);
  console->type(kPassphrase);
  const auto created = run(manager().create_with_passphrase(kCheap));
  ASSERT_TRUE(created.ok) << created.error;
  EXPECT_EQ(created.value.header().source, MasterKeySource::passphrase);
  EXPECT_EQ(console->prompts, (std::vector<std::string>{"New master passphrase: ", "Again: "}));
  EXPECT_TRUE(run(files->exists("/var/lib/lugh/keyring")));

  console->type(kPassphrase);
  const auto opened = run(manager().open());
  ASSERT_TRUE(opened.ok) << opened.error;
  EXPECT_EQ(opened.value.id_hex(), created.value.id_hex());

  console->type(kPassphrase + "!");
  const auto wrong = run(manager().open());
  EXPECT_FALSE(wrong.ok);
  EXPECT_NE(wrong.error.find("does not open"), std::string::npos);

  const auto none = run(manager().open());
  EXPECT_FALSE(none.ok);
  EXPECT_NE(none.error.find("none was given"), std::string::npos);
}

TEST_F(KeyringManagerTest, APassphraseThatIsTooShort) {
  console->type("fifteen chars!!");
  const auto created = run(manager().create_with_passphrase(kCheap));
  EXPECT_FALSE(created.ok);
  EXPECT_NE(created.error.find("16 characters"), std::string::npos);
  EXPECT_FALSE(run(files->exists("/var/lib/lugh/keyring")));
}

TEST_F(KeyringManagerTest, PassphrasesThatDiffer) {
  console->type(kPassphrase);
  console->type(kPassphrase + " ");
  const auto created = run(manager().create_with_passphrase(kCheap));
  EXPECT_FALSE(created.ok);
  EXPECT_NE(created.error.find("differ"), std::string::npos);
  EXPECT_FALSE(run(files->exists("/var/lib/lugh/keyring")));
}

TEST_F(KeyringManagerTest, ARotationIsSavedAndReopened) {
  initialise();
  auto keys = manager();
  auto keyring = run(keys.open()).value;
  ASSERT_TRUE(keyring.rotate("users", *random).ok);
  ASSERT_TRUE(run(keys.save(keyring)).ok);

  const auto reopened = run(manager().open());
  ASSERT_TRUE(reopened.ok) << reopened.error;
  ASSERT_NE(reopened.value.current("users"), nullptr);
  EXPECT_EQ(reopened.value.current("users")->epoch, 1u);
}

TEST_F(KeyringManagerTest, AFailedWriteSavesNothing) {
  auto keys = manager();
  const auto created = run(keys.create_for_credential());
  files->fail_writes = true;
  EXPECT_FALSE(run(keys.save_new(created.value.keyring)).ok);
  EXPECT_FALSE(run(files->exists("/var/lib/lugh/keyring")));
}

TEST_F(KeyringManagerTest, NoRandomnessNoKeyring) {
  random->fail = true;
  EXPECT_FALSE(run(manager().create_for_credential()).ok);
}
