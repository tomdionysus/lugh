//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "lugh/audit/audit_log.h"
#include "lugh/authn/authenticator.h"
#include "lugh/authn/totp.h"
#include "lugh/core/encoding.h"
#include "lugh/directory/directory.h"
#include "lugh/store/tables.h"
#include "lugh/test/fixtures/counting_random.h"
#include "lugh/test/fixtures/logger_mock.h"
#include "lugh/test/fixtures/manual_clock.h"
#include "lugh/test/fixtures/memory_store.h"
#include "lugh/test/fixtures/pools.h"
#include "lugh/test/fixtures/run.h"

// Every table, with the directory's indexes, as main opens them.
inline std::vector<lugh::store::TableSpec> all_tables() {
  std::vector<lugh::store::TableSpec> out;
  const auto indexed = lugh::directory::table_specs();
  for (const auto name : lugh::store::kTables) {
    lugh::store::TableSpec spec{std::string(name), {}};
    for (const auto& one : indexed) {
      if (one.name == name) spec = one;
    }
    out.push_back(std::move(spec));
  }
  return out;
}

// Costs small enough for a test to hash freely; the hashing is Argon2id all the same.
inline constexpr lugh::crypto::Argon2Params kTestArgon2{64, 1, 1};

// The directory and authn, wired as main wires them, over a MemoryStore, a ManualClock and
// CountingRandom, with hashing on a pool of real threads. The helpers here run their
// coroutines to the end, for tests that are not coroutines.
class AuthnRig {
 public:
  explicit AuthnRig(lugh::authn::BreachedPasswords breached = {}, lugh::authn::Authenticator::Settings settings = {}) {
    audit = run(lugh::audit::AuditLog::open(logger, store, clock)).value;
    directory = std::make_shared<lugh::directory::Directory>(logger, store, random, clock, audit);
    passwords = std::make_shared<lugh::authn::Passwords>(logger, store, random, clock, audit, test_pool(), kTestArgon2, lugh::authn::PasswordRules{},
                                                         std::move(breached));
    factors = std::make_shared<lugh::authn::Factors>(logger, store, random, clock, audit, test_pool(), kTestArgon2);
    directory->dependent_add(passwords);
    directory->dependent_add(factors);
    policies = std::make_shared<lugh::authn::Policies>(store, directory, audit);
    links = std::make_shared<lugh::authn::EnrolmentLinks>(store, random, clock, directory, audit);
    authenticator = std::make_shared<lugh::authn::Authenticator>(logger, clock, directory, passwords, factors, policies, links, audit, settings);
  }

  lugh::directory::User person(const std::string& name) {
    auto made = run(directory->create_user(admin, {lugh::directory::Kind::person, name, name + "@example.com", name}));
    EXPECT_TRUE(made.ok()) << made.message;
    return made.value;
  }

  // The code an authenticator app would show now for a base32 secret.
  std::string code_for(const lugh::Secret& secret, std::int64_t steps_ahead = 0) const {
    const auto raw = lugh::encoding::base32_decode(secret.reveal());
    const auto now = lugh::system::unix_seconds(*clock);
    return lugh::authn::totp_code(*raw, lugh::authn::totp_step(now) + static_cast<std::uint64_t>(steps_ahead));
  }

  // The actions in the audit log, in order.
  std::vector<std::string> actions() const {
    std::vector<std::string> out;
    for (const auto& entry : run(audit->entries(1, 100000))) out.push_back(entry.event.action);
    return out;
  }

  bool audited(const std::string& action) const {
    for (const auto& one : actions()) {
      if (one == action) return true;
    }
    return false;
  }

  // A person all the way through enrolment: a link, a password, a TOTP factor. Leaves
  // `secret` holding the factor's secret and `recovery` the codes.
  lugh::directory::User enrolled(const std::string& name, const std::string& password = "correct horse battery") {
    const auto user = person(name);
    const auto token = run(links->issue(admin, user.id));
    EXPECT_TRUE(token.ok()) << token.message;
    const auto redeemed = run(authenticator->redeem(token.value, lugh::Secret(password), "192.0.2.1"));
    EXPECT_EQ(redeemed.kind, lugh::authn::Step::Kind::next);
    auto setup = run(authenticator->enrol_begin(redeemed.sign_in, "192.0.2.1"));
    EXPECT_TRUE(setup.ok()) << setup.message;
    auto done = run(authenticator->enrol_confirm(redeemed.sign_in, setup.value.factor_id, code_for(setup.value.secret), "192.0.2.1"));
    EXPECT_EQ(done.kind, lugh::authn::Step::Kind::next);
    secret = setup.value.secret;
    recovery = std::move(done.recovery_codes);
    // Past the step the confirming code used, so the next code is a new one.
    clock->advance(std::chrono::seconds(30));
    return *run(directory->user(user.id));
  }

  lugh::audit::Actor admin{"admin", "192.0.2.10"};
  std::shared_ptr<MockLogger> logger = std::make_shared<MockLogger>();
  std::shared_ptr<MemoryStore> store = std::make_shared<MemoryStore>(all_tables());
  std::shared_ptr<ManualClock> clock = std::make_shared<ManualClock>();
  std::shared_ptr<CountingRandom> random = std::make_shared<CountingRandom>();
  std::shared_ptr<lugh::audit::AuditLog> audit;
  std::shared_ptr<lugh::directory::Directory> directory;
  std::shared_ptr<lugh::authn::Passwords> passwords;
  std::shared_ptr<lugh::authn::Factors> factors;
  std::shared_ptr<lugh::authn::Policies> policies;
  std::shared_ptr<lugh::authn::EnrolmentLinks> links;
  std::shared_ptr<lugh::authn::Authenticator> authenticator;

  lugh::Secret secret;
  std::vector<lugh::Secret> recovery;
};
