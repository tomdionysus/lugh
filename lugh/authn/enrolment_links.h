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

#include "dannan/contract/time_source.h"
#include "lugh/audit/audit_log.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/secret.h"
#include "lugh/core/task.h"
#include "lugh/directory/directory.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::authn {

// One-time links that let a person who is not enrolled set a password and enrol a second
// factor: a new user, or one whose factors an administrator reset. In the `grants` table,
// keyed by the SHA-256 of the token, so the table holds nothing that would work as a link.
// Spent by removing the record at the version read, so a link works once even when two
// requests race with it.
//
// Every operation takes Dannan's shape (core/completion.h). Made with std::make_shared.
class EnrolmentLinks : public std::enable_shared_from_this<EnrolmentLinks> {
 public:
  static constexpr const char* kTable = "grants";
  static constexpr std::size_t kTokenBytes = 32;

  EnrolmentLinks(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<directory::Directory> directory,
                 std::shared_ptr<audit::AuditLog> audit, std::chrono::seconds lifetime = std::chrono::hours(72));

  // A new token, base64url, for a person who is not enrolled. Any earlier link of theirs
  // stops working.
  void issue(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<Secret>> done);

  // The user a live token is for, without spending it.
  void peek(Secret token, Deadline deadline, Executor executor, Done<Outcome<std::string>> done) const;

  struct Link;
  // The whole of a live link, without spending it.
  void link(Secret token, Deadline deadline, Executor executor, Done<Outcome<Link>> done) const;

  // Spends the token: the user it was for.
  void spend(Secret token, audit::Actor actor, Deadline deadline, Executor executor, Done<Outcome<std::string>> done);

  // Genesis's one allowance (authn/genesis.h): root, who is not enrolled, may go from their
  // password straight to enrolment, once. The password was made by genesis and shown only
  // to whoever ran it, so it stands where a link would. Spent when enrolment finishes.
  void first_sign_in_allow(audit::Actor actor, std::string user_id, Deadline deadline, Executor executor, Done<Outcome<>> done);
  void first_sign_in_allowed(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<bool>> done) const;
  void first_sign_in_spend(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<>> done);

  struct Link {
    std::string user_id;
    std::uint64_t issued = 0;
    std::uint64_t expires = 0;
  };

  static SecureBuffer encode(const Link& link);
  static std::optional<Link> decode(std::span<const unsigned char> value);

 private:
  static std::optional<std::string> _key(const Secret& token);
  // The link and its record's version.
  void _live(std::string key, Executor executor, Done<Outcome<std::pair<Link, std::uint64_t>>> done) const;
  void _record(audit::Event event, Executor executor, std::function<void()> then) const;

  store::StoreCalls _calls;
  const dannan::contract::WallClock& _wall;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<audit::AuditLog> _audit;
  std::chrono::seconds _lifetime;
};

}  // namespace lugh::authn
