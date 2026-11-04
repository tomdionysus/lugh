//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <string>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"
#include "lugh/apps/apps.h"
#include "lugh/audit/audit_log.h"
#include "lugh/core/completion.h"
#include "lugh/core/status.h"
#include "lugh/http/outbound.h"
#include "lugh/oauth/issuer.h"
#include "lugh/session/sessions.h"

namespace lugh::oauth {

// OIDC Back-Channel Logout 1.0: when a session ends, however it ends, every application signed in
// through it that registered a URI is told, by a logout token posted to that URI. Refused or
// unanswered, the post is tried again with the wait doubling, for an hour; delivery and giving up
// are both audited. A fresh token goes with each try, since one lives two minutes.
//
// What waits is held in memory: a node that restarts forgets it. Safe from any number of threads;
// made with std::make_shared.
class BackchannelLogout : public std::enable_shared_from_this<BackchannelLogout> {
 public:
  struct Settings {
    std::chrono::seconds first_wait{30};
    std::chrono::seconds give_up_after{std::chrono::hours(1)};
    Deadline attempt{std::chrono::seconds(10)};
  };

  BackchannelLogout(std::shared_ptr<apps::Apps> apps, std::shared_ptr<const TokenIssuer> issuer, std::shared_ptr<http::Outbound> outbound,
                    std::shared_ptr<audit::AuditLog> audit, const dannan::contract::TimeSource& time, Settings settings);

  // Queues a logout for each application of the session's. Never waits.
  void session_ended(const session::Session& session);

  // Tries everything due that is not already being tried, and answers when those tries are over.
  void deliver_due(Deadline deadline, Executor executor, Done<Status> done);

  // How many logouts have not yet been delivered or given up on.
  std::size_t waiting() const;

 private:
  struct Delivery {
    std::string client_id;
    std::string user_id;
    std::string sid;
    dannan::contract::TimePoint first;
    dannan::contract::TimePoint next;
    std::chrono::seconds wait{0};
    bool trying = false;
  };

  void _attempt(std::uint64_t id, Delivery delivery, Executor executor, std::function<void()> then);
  void _delivered(std::uint64_t id, const Delivery& delivery, Executor executor, std::function<void()> then);
  void _forget(std::uint64_t id);
  void _failed(std::uint64_t id, const Delivery& delivery, const std::string& why, Executor executor, std::function<void()> then);

  std::shared_ptr<apps::Apps> _apps;
  std::shared_ptr<const TokenIssuer> _issuer;
  std::shared_ptr<http::Outbound> _outbound;
  std::shared_ptr<audit::AuditLog> _audit;
  const dannan::contract::TimeSource& _time;
  Settings _settings;

  mutable dannan::contract::Mutex _mutex;
  std::map<std::uint64_t, Delivery> _waiting DANNAN_GUARDED_BY(_mutex);
  std::uint64_t _next_id DANNAN_GUARDED_BY(_mutex) = 0;
};

}  // namespace lugh::oauth
