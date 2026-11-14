//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>
#include <sys/stat.h>

#include <algorithm>
#include <random>

#include "lugh/test/fixtures/node_process.h"

// `lugh-node init`, and the start that needs what it made.
//
// With a credential: init writes 32 raw bytes to standard output and the keyring to the
// state directory, then performs genesis, showing root's password once on standard error
// and keeping it nowhere; it refuses a terminal for that output, and never replaces a
// keyring. A start without the credential, or with the wrong one, or with no keyring, fails
// saying why; with it, the service comes up. With a passphrase: init asks twice on standard
// input, and every start asks again.

namespace {

using namespace node_process;

bool base64url(const std::string& text) {
  return std::all_of(text.begin(), text.end(), [](char c) { return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == '_'; });
}

unsigned mode_of(const std::filesystem::path& path) {
  struct stat status{};
  ::stat(path.c_str(), &status);
  return status.st_mode & 0777;
}

std::string hex(const std::string& bytes) {
  static constexpr char kDigits[] = "0123456789abcdef";
  std::string out;
  for (const unsigned char c : bytes) {
    out.push_back(kDigits[c >> 4]);
    out.push_back(kDigits[c & 0x0f]);
  }
  return out;
}

}  // namespace

TEST(NodeProcessInit, WithNoKeyringTheServiceSaysToRunInit) {
  Workspace workspace;
  const auto credentials = workspace.path("credentials");
  std::filesystem::create_directories(credentials);
  Serving serving(workspace, workspace.path("state"), credentials);
  EXPECT_FALSE(serving.up());
  const auto text = serving.stop();
  EXPECT_NE(text.find("lugh-node init"), std::string::npos) << text;
}

TEST(NodeProcessInit, WithACredential) {
  Workspace workspace;
  const auto state = workspace.path("state");
  const auto credentials = workspace.path("credentials");
  std::filesystem::create_directories(credentials);

  const auto made = init(workspace, state);
  ASSERT_EQ(made.status, 0) << made.err;
  EXPECT_EQ(made.out.size(), 32u) << "init writes the 32-byte master key to standard output";
  ASSERT_TRUE(std::filesystem::is_regular_file(state / "keyring"));
  EXPECT_EQ(mode_of(state / "keyring"), 0600u) << "the keyring is private";
  EXPECT_EQ(mode_of(state), 0700u) << "the state directory is private";
  EXPECT_EQ(made.err.find(hex(made.out)), std::string::npos) << "init does not echo the key";

  const auto password = root_password(made.err);
  EXPECT_EQ(password.size(), 24u) << made.err;
  EXPECT_TRUE(base64url(password)) << "genesis shows root's password: " << made.err;
  EXPECT_EQ(made.out.find(password), std::string::npos) << "not on standard output";
  EXPECT_FALSE(password.empty() || on_disk(state, password)) << "nor anywhere on disk";
  EXPECT_TRUE(std::filesystem::is_regular_file(state / "store" / "users.log")) << "genesis makes the store";

  write_file(credentials / kCredential, made.out);
  const auto keyring = read_file(state / "keyring");
  EXPECT_EQ(keyring.find(made.out), std::string::npos) << "the master key is not in the keyring";

  const auto again = init(workspace, state);
  EXPECT_NE(again.status, 0) << "a second init fails";
  EXPECT_TRUE(again.out.empty()) << "a second init writes no key";
  EXPECT_EQ(root_password(again.err), "") << "a second init makes no second root";
  EXPECT_EQ(read_file(state / "keyring"), keyring) << "a second init leaves the keyring";

  {
    Serving serving(workspace, state, std::nullopt);
    EXPECT_FALSE(serving.up()) << "no credential: the service does not start";
    const auto text = serving.stop();
    EXPECT_NE(text.find(kCredential), std::string::npos) << "no credential: it names the credential\n" << text;
  }
  {
    Serving serving(workspace, state, credentials);
    EXPECT_TRUE(serving.up()) << "with the credential: the service comes up\n" << serving.log();
    const auto text = serving.stop();
    EXPECT_NE(text.find("Opened keyring"), std::string::npos) << text;
  }

  std::string wrong(32, '\0');
  std::random_device random;
  for (auto& byte : wrong) byte = static_cast<char>(random());
  write_file(credentials / kCredential, wrong);
  {
    Serving serving(workspace, state, credentials);
    EXPECT_FALSE(serving.up()) << "the wrong credential: the service does not start";
    const auto text = serving.stop();
    EXPECT_NE(text.find("does not open"), std::string::npos) << text;
  }
}

// A terminal on standard output would show the key: refused, and nothing made.
TEST(NodeProcessInit, RefusesATerminal) {
  Workspace workspace;
  const auto state = workspace.path("tty-state");
  const auto ran = run(workspace, {"init", "--state-directory", state.string()}, {.environment = environment(), .input = std::nullopt, .terminal = true});
  EXPECT_NE(ran.status, 0);
  EXPECT_NE(ran.out.find("terminal"), std::string::npos) << ran.out;
  EXPECT_FALSE(std::filesystem::exists(state / "keyring"));
}

TEST(NodeProcessInit, WithAPassphrase) {
  Workspace workspace;
  const auto state = workspace.path("state");
  const std::string passphrase = "correct horse battery staple";

  const auto short_one = init(workspace, state, {"--passphrase"}, "too short\ntoo short\n");
  EXPECT_NE(short_one.status, 0);
  EXPECT_NE(short_one.err.find("16 characters"), std::string::npos) << short_one.err;

  const auto differ = init(workspace, state, {"--passphrase"}, passphrase + "\n" + passphrase + "!\n");
  EXPECT_NE(differ.status, 0);
  EXPECT_NE(differ.err.find("differ"), std::string::npos) << differ.err;
  EXPECT_FALSE(std::filesystem::exists(state / "keyring")) << "and nothing is made";

  const auto made = init(workspace, state, {"--passphrase"}, passphrase + "\n" + passphrase + "\n");
  ASSERT_EQ(made.status, 0) << made.err;
  EXPECT_TRUE(made.out.empty()) << "nothing on standard output";
  EXPECT_TRUE(std::filesystem::is_regular_file(state / "keyring"));
  EXPECT_EQ(root_password(made.err).size(), 24u) << made.err;

  {
    Serving serving(workspace, state, std::nullopt, passphrase + "\n");
    EXPECT_TRUE(serving.up()) << "with the passphrase: the service comes up\n" << serving.log();
    serving.stop();
  }
  {
    Serving serving(workspace, state, std::nullopt, std::string("not the passphrase at all\n"));
    EXPECT_FALSE(serving.up());
    const auto text = serving.stop();
    EXPECT_NE(text.find("does not open"), std::string::npos) << text;
  }
  {
    Serving serving(workspace, state, std::nullopt, std::string());
    EXPECT_FALSE(serving.up());
    const auto text = serving.stop();
    EXPECT_NE(text.find("none was given"), std::string::npos) << text;
  }
}
