//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>

#include "lugh/audit/audit_log.h"
#include "lugh/core/outcome.h"
#include "lugh/core/secret.h"
#include "lugh/core/task.h"
#include "lugh/directory/directory.h"
#include "lugh/store/store.h"
#include "lugh/system/clock.h"
#include "lugh/system/random.h"

namespace lugh::authn {

// One-time links that let a person who is not enrolled set a password and enrol a second
// factor: a new user, or one whose factors an administrator reset. In the `grants` table,
// keyed by the SHA-256 of the token, so the table holds nothing that would work as a link.
// Spent by removing the record at the version read, so a link works once even when two
// requests race with it.
class EnrolmentLinks {
 public:
  static constexpr const char* kTable = "grants";
  static constexpr std::size_t kTokenBytes = 32;

  EnrolmentLinks(std::shared_ptr<store::Store> store, std::shared_ptr<system::Random> random, std::shared_ptr<system::Clock> clock,
                 std::shared_ptr<directory::Directory> directory, std::shared_ptr<audit::AuditLog> audit,
                 std::chrono::seconds lifetime = std::chrono::hours(72));

  // A new token, base64url, for a person who is not enrolled. Any earlier link of theirs
  // stops working.
  Task<Outcome<Secret>> issue(audit::Actor actor, std::string user_id);

  // The user a live token is for, without spending it.
  Task<Outcome<std::string>> peek(Secret token) const;

  struct Link;
  // The whole of a live link, without spending it.
  Task<Outcome<Link>> link(Secret token) const;

  // Spends the token: the user it was for.
  Task<Outcome<std::string>> spend(Secret token, audit::Actor actor);

  // Genesis's one allowance (authn/genesis.h): root, who is not enrolled, may go from their
  // password straight to enrolment, once. The password was made by genesis and shown only
  // to whoever ran it, so it stands where a link would. Spent when enrolment finishes.
  Task<Outcome<>> first_sign_in_allow(audit::Actor actor, std::string user_id);
  Task<bool> first_sign_in_allowed(std::string user_id) const;
  Task<void> first_sign_in_spend(std::string user_id);

  struct Link {
    std::string user_id;
    std::uint64_t issued = 0;
    std::uint64_t expires = 0;
  };

  static SecureBytes encode(const Link& link);
  static std::optional<Link> decode(std::span<const unsigned char> value);

 private:
  static std::optional<std::string> _key(const Secret& token);
  // The link and its record's version.
  Task<Outcome<std::pair<Link, std::uint64_t>>> _live(std::string key) const;

  std::shared_ptr<store::Store> _store;
  std::shared_ptr<system::Random> _random;
  std::shared_ptr<system::Clock> _clock;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<audit::AuditLog> _audit;
  std::chrono::seconds _lifetime;
};

}  // namespace lugh::authn
