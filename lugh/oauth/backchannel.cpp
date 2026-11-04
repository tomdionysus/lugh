//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/oauth/backchannel.h"

#include <atomic>
#include <vector>

namespace lugh::oauth {

namespace {

constexpr Deadline kStepDeadline = std::chrono::seconds(15);

}  // namespace

BackchannelLogout::BackchannelLogout(std::shared_ptr<apps::Apps> apps, std::shared_ptr<const TokenIssuer> issuer, std::shared_ptr<http::Outbound> outbound,
                                     std::shared_ptr<audit::AuditLog> audit, const dannan::contract::TimeSource& time, Settings settings)
    : _apps(std::move(apps)), _issuer(std::move(issuer)), _outbound(std::move(outbound)), _audit(std::move(audit)), _time(time), _settings(settings) {}

void BackchannelLogout::session_ended(const session::Session& session) {
  const auto now = _time.now();
  dannan::contract::Lock state(_mutex);
  for (const auto& client_id : session.apps) {
    _waiting.emplace(_next_id++, Delivery{client_id, session.user_id, session.sid, now, now, _settings.first_wait, false});
  }
}

std::size_t BackchannelLogout::waiting() const {
  dannan::contract::Lock state(_mutex);
  return _waiting.size();
}

void BackchannelLogout::deliver_due(Deadline deadline, Executor executor, Done<Status> done) {
  auto answer =
      Completion<Status>::start(deadline, executor, std::move(done), [] { return Status::failure("the logouts were not tried within the deadline"); });
  std::vector<std::pair<std::uint64_t, Delivery>> due;
  {
    const auto now = _time.now();
    dannan::contract::Lock state(_mutex);
    for (auto& [id, delivery] : _waiting) {
      if (delivery.trying || delivery.next > now) continue;
      delivery.trying = true;
      due.emplace_back(id, delivery);
    }
  }
  if (due.empty()) return answer->finish(Status::success());
  auto left = std::make_shared<std::atomic<std::size_t>>(due.size());
  for (auto& [id, delivery] : due) {
    _attempt(id, std::move(delivery), executor, [answer, left] {
      if (left->fetch_sub(1) == 1) answer->finish(Status::success());
    });
  }
}

void BackchannelLogout::_attempt(std::uint64_t id, Delivery delivery, Executor executor, std::function<void()> then) {
  auto self = shared_from_this();
  _apps->app(delivery.client_id, kStepDeadline, executor, [=](Outcome<std::optional<apps::App>> app) {
    if (!app.ok()) return self->_failed(id, delivery, "the application could not be read: " + app.message, executor, then);
    // An application since removed, or that no longer asks to be told, is owed nothing.
    if (!app.value || app.value->backchannel_logout_uri.empty()) {
      self->_forget(id);
      return then();
    }
    const auto token = self->_issuer->logout_token(delivery.client_id, delivery.user_id, delivery.sid);
    if (!token) return self->_failed(id, delivery, "no key signs yet", executor, then);
    self->_outbound->post_form(app.value->backchannel_logout_uri, "logout_token=" + *token, self->_settings.attempt, executor, [=](Outcome<unsigned> posted) {
      if (!posted.ok()) return self->_failed(id, delivery, posted.message, executor, then);
      if (posted.value < 200 || posted.value >= 300) return self->_failed(id, delivery, "it answered " + std::to_string(posted.value), executor, then);
      self->_delivered(id, delivery, executor, then);
    });
  });
}

void BackchannelLogout::_forget(std::uint64_t id) {
  dannan::contract::Lock state(_mutex);
  _waiting.erase(id);
}

void BackchannelLogout::_delivered(std::uint64_t id, const Delivery& delivery, Executor executor, std::function<void()> then) {
  _forget(id);
  _audit->record(audit::Event{"logout.backchannel", "lugh", delivery.user_id, {}, delivery.client_id + " told, sid " + delivery.sid}, kStepDeadline, executor,
                 [then](Status) { then(); });
}

void BackchannelLogout::_failed(std::uint64_t id, const Delivery& delivery, const std::string& why, Executor executor, std::function<void()> then) {
  const auto now = _time.now();
  {
    dannan::contract::Lock state(_mutex);
    const auto found = _waiting.find(id);
    if (found == _waiting.end()) return then();
    if (now + found->second.wait - found->second.first <= _settings.give_up_after) {
      found->second.next = now + found->second.wait;
      found->second.wait *= 2;
      found->second.trying = false;
      return then();
    }
    _waiting.erase(found);
  }
  _audit->record(audit::Event{"logout.backchannel.failed", "lugh", delivery.user_id, {}, delivery.client_id + " not told, sid " + delivery.sid + ": " + why},
                 kStepDeadline, executor, [then](Status) { then(); });
}

}  // namespace lugh::oauth
