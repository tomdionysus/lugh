#pragma once

#include <memory>
#include <string>
#include <vector>

#include "fakes/fixed_random.h"
#include "fakes/map_environment.h"
#include "fakes/memory_files.h"
#include "fakes/scripted_console.h"
#include "helpers/pools.h"
#include "helpers/run.h"
#include "keys/keyring_manager.h"
#include "mocks/logger_mock.h"
#include "store/sealed_store.h"

// A SealedStore over MemoryFiles, with a keyring of its own, that can be opened again on
// the same files to see what survived.
class SealedStoreRig {
 public:
  explicit SealedStoreRig(std::vector<lugh::store::TableSpec> tables) : tables(std::move(tables)) {
    lugh::keys::KeyringHeader header;
    header.id = random->bytes(lugh::keys::kKeyringIdBytes);
    keyring = lugh::keys::Keyring::create(header, lugh::Bytes(lugh::keys::kMasterKeyBytes, 0x5a)).value;
  }

  lugh::Result<std::shared_ptr<lugh::store::SealedStore>> open() {
    // The keyring as last saved, as a restart would have it.
    if (const auto saved = files->get("/state/keyring")) {
      keyring = lugh::keys::Keyring::open(*saved, lugh::Bytes(lugh::keys::kMasterKeyBytes, 0x5a)).value;
    }
    return run(lugh::store::SealedStore::open(logger, files, random, keyrings, keyring, "/state/store", tables));
  }

  std::shared_ptr<lugh::store::SealedStore> open_ok() {
    auto opened = open();
    EXPECT_TRUE(opened.ok) << opened.error;
    return opened.value;
  }

  lugh::Bytes file(const std::string& table) const { return files->get("/state/store/" + table + ".log").value_or(lugh::Bytes{}); }
  void file_set(const std::string& table, lugh::Bytes bytes) { files->put("/state/store/" + table + ".log", std::move(bytes)); }

  std::vector<lugh::store::TableSpec> tables;
  std::shared_ptr<MockLogger> logger = std::make_shared<MockLogger>();
  std::shared_ptr<MemoryFiles> files = std::make_shared<MemoryFiles>();
  std::shared_ptr<FixedRandom> random = std::make_shared<FixedRandom>();
  std::shared_ptr<lugh::keys::KeyringManager> keyrings = std::make_shared<lugh::keys::KeyringManager>(
      logger, files, random, std::make_shared<ScriptedConsole>(), std::make_shared<MapEnvironment>(), "/state", test_pool());
  lugh::keys::Keyring keyring;
};

// An index for tests: a value "name:rest" is found by its name.
inline lugh::store::IndexSpec name_index() {
  return lugh::store::IndexSpec{"name", [](std::span<const unsigned char> value) {
                                  const std::string text(value.begin(), value.end());
                                  const auto colon = text.find(':');
                                  if (colon == std::string::npos) return std::vector<std::string>{};
                                  return std::vector<std::string>{text.substr(0, colon)};
                                }};
}

inline std::string text(const lugh::SecureBytes& value) { return std::string(value.begin(), value.end()); }

// A value to write: the store takes SecureBytes.
inline lugh::SecureBytes secure(std::string_view value) { return lugh::SecureBytes(value.begin(), value.end()); }
