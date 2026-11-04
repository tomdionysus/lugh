//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/session/sessions.h"

#include "dannan/identity/crypto.h"
#include "lugh/core/codec.h"
#include "lugh/core/encoding.h"
#include "lugh/core/steps.h"
#include "lugh/scopes/scope.h"

namespace lugh::session {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr std::size_t kCsrfBytes = 32;
constexpr std::size_t kSidBytes = 16;
constexpr Deadline kStepDeadline = std::chrono::seconds(30);
constexpr const char* kChangeLate = "the sessions did not answer within the deadline; the change may yet be made";

std::span<const unsigned char> bytes_of(std::string_view text) { return {reinterpret_cast<const unsigned char*>(text.data()), text.size()}; }

}  // namespace

Sessions::Sessions(std::shared_ptr<store::Store> store, const dannan::contract::WallClock& wall, std::shared_ptr<directory::Directory> directory,
                   std::shared_ptr<scopes::Grants> grants, std::shared_ptr<audit::AuditLog> audit, Settings settings)
    : _calls(std::move(store)), _wall(wall), _directory(std::move(directory)), _grants(std::move(grants)), _audit(std::move(audit)), _settings(settings) {}

std::string Sessions::key_of(std::string_view handle) { return dannan::identity::hex(dannan::identity::sha256(bytes_of(handle))); }

SecureBuffer Sessions::encode(const Session& session) {
  SecureWriter writer;
  writer.u8(kFormat);
  writer.string(session.user_id);
  writer.string(session.sid);
  writer.u8(static_cast<std::uint8_t>(session.acr));
  writer.u32(static_cast<std::uint32_t>(session.amr.size()));
  for (const auto& one : session.amr) writer.string(one);
  writer.u64(session.auth_time);
  writer.u64(session.created);
  writer.u64(session.last_seen);
  writer.bytes(session.csrf);
  writer.u32(static_cast<std::uint32_t>(session.scopes.size()));
  for (const auto& one : session.scopes) writer.string(one);
  return writer.take();
}

std::optional<Session> Sessions::decode(std::span<const unsigned char> value) {
  return decode_whole<Session>(value, [](dannan::net::Reader& reader) -> std::optional<Session> {
    if (reader.u8() != kFormat) return std::nullopt;
    Session session;
    session.user_id = reader.string(kMostFieldBytes);
    session.sid = reader.string(kMostFieldBytes);
    const auto acr = reader.u8();
    if (acr < static_cast<std::uint8_t>(authn::Assurance::pwd) || acr > static_cast<std::uint8_t>(authn::Assurance::phr)) return std::nullopt;
    session.acr = static_cast<authn::Assurance>(acr);
    const auto amr = reader.u32();
    if (amr > 8) return std::nullopt;
    for (std::uint32_t i = 0; i < amr; ++i) session.amr.push_back(reader.string(32));
    session.auth_time = reader.u64();
    session.created = reader.u64();
    session.last_seen = reader.u64();
    const auto csrf = reader.view_bytes(kCsrfBytes);
    if (csrf.size() != kCsrfBytes) return std::nullopt;
    session.csrf = SecureBuffer(csrf.begin(), csrf.end());
    const auto scopes = reader.u32();
    if (scopes > 4096) return std::nullopt;
    for (std::uint32_t i = 0; i < scopes; ++i) session.scopes.push_back(reader.string(scopes::kMostScopeBytes));
    return session;
  });
}

std::string Sessions::csrf_token(const Session& session) {
  const auto mac = dannan::identity::hmac_sha256(session.csrf, bytes_of("lugh csrf"));
  return encoding::base64url(mac);
}

bool Sessions::csrf_ok(const Session& session, std::string_view token) {
  const auto expected = csrf_token(session);
  return dannan::identity::constant_time_equal(bytes_of(expected), bytes_of(token));
}

bool Sessions::_live(const Session& session, std::uint64_t now) const {
  return now < session.last_seen + static_cast<std::uint64_t>(_settings.idle.count()) &&
         now < session.created + static_cast<std::uint64_t>(_settings.absolute.count());
}

void Sessions::open(Deadline deadline, Executor executor, Done<Status> done) {
  auto answer =
      Completion<Status>::start(deadline, executor, std::move(done), [] { return Status::failure("the sessions were not read within the deadline"); });
  auto self = shared_from_this();
  _calls.list_settled(kTable, executor, [self, answer](Outcome<std::vector<store::Record>> records) {
    if (!records.ok()) return answer->finish(Status::failure(records.message));
    std::map<std::string, Session> held;
    for (const auto& record : records.value) {
      auto session = decode(record.value);
      if (!session) return answer->finish(Status::failure("the session record " + record.key + " does not decode"));
      session->key = record.key;
      session->version = record.version;
      held.emplace(record.key, std::move(*session));
    }
    dannan::contract::Lock state(self->_mutex);
    self->_saved_seen.clear();
    for (const auto& [key, session] : held) self->_saved_seen[key] = session.last_seen;
    self->_held = std::move(held);
    answer->finish(Status::success());
  });
}

void Sessions::create(audit::Actor actor, std::string user_id, authn::Assurance acr, std::vector<std::string> amr, Deadline deadline, Executor executor,
                      Done<Outcome<Created>> done) {
  using Answer = Outcome<Created>;
  auto answer = answering<Created>(deadline, executor, std::move(done), kChangeLate);
  auto handle = std::make_shared<Secret>(text_secret(encoding::base64url(secure_random(kHandleBytes))));
  auto session = std::make_shared<Session>();
  session->key = key_of(secret_text(*handle));
  session->user_id = user_id;
  session->sid = encoding::base64url(dannan::identity::random_bytes(kSidBytes));
  session->acr = acr;
  session->amr = std::move(amr);
  session->auth_time = session->created = session->last_seen = _now();
  session->csrf = secure_random(kCsrfBytes);

  auto self = shared_from_this();
  _grants->effective(user_id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> scopes) {
    if (!scopes.ok()) return answer->finish(Answer::from(scopes));
    session->scopes = std::move(scopes.value);
    self->_calls.put_settled(kTable, session->key, encode(*session), 0, executor, [=](store::Write written) {
      if (!written.ok()) return answer->finish(Answer::failure(Fault::failed, written.message));
      session->version = written.version;
      {
        dannan::contract::Lock state(self->_mutex);
        self->_held[session->key] = *session;
        self->_saved_seen[session->key] = session->last_seen;
      }
      self->_audit->record(audit::Event{"session.start", actor.id, user_id, actor.source, std::string(authn::acr(acr)) + ", sid " + session->sid},
                           kStepDeadline, executor,
                           [answer, handle, session](Status) { answer->finish(Answer::success(Created{Secret(handle->reveal()), *session})); });
    });
  });
}

std::optional<Session> Sessions::find(std::string_view handle) {
  if (handle.empty() || handle.size() > 128) return std::nullopt;
  const auto key = key_of(handle);
  const auto now = _now();
  dannan::contract::Lock state(_mutex);
  const auto found = _held.find(key);
  if (found == _held.end() || !_live(found->second, now)) return std::nullopt;
  found->second.last_seen = now;
  return found->second;
}

void Sessions::_remove(std::string key, std::string why, Executor executor, std::function<void()> then) {
  std::optional<Session> session;
  {
    dannan::contract::Lock state(_mutex);
    const auto found = _held.find(key);
    if (found != _held.end()) session = found->second;
    _held.erase(key);
    _saved_seen.erase(key);
  }
  // Gone from memory at once, so the handle stops working before the disk has answered.
  auto self = shared_from_this();
  _calls.remove_settled(kTable, key, std::nullopt, executor, [self, session, why, executor, then](store::Write) {
    if (!session) return then();
    self->_audit->record(audit::Event{"session.end", "lugh", session->user_id, {}, why + ", sid " + session->sid}, kStepDeadline, executor,
                         [then](Status) { then(); });
  });
}

void Sessions::end(audit::Actor actor, std::string handle, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  const auto key = key_of(handle);
  bool held = false;
  {
    dannan::contract::Lock state(_mutex);
    held = _held.count(key) > 0;
  }
  if (!held) return answer->finish(Outcome<>::success());
  _remove(key, "signed out from " + actor.source, executor, [answer] { answer->finish(Outcome<>::success()); });
}

void Sessions::_refresh_one(std::string key, Executor executor, std::function<void()> then) {
  std::optional<Session> session;
  {
    dannan::contract::Lock state(_mutex);
    const auto found = _held.find(key);
    if (found != _held.end()) session = found->second;
  }
  if (!session) return then();
  if (!_live(*session, _now())) return _remove(key, "expired", executor, then);

  auto self = shared_from_this();
  _directory->user(session->user_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::User>> user) {
    // A read that failed leaves the session as it was: it is tried again next time.
    if (!user.ok()) return then();
    if (!user.value) return self->_remove(key, "the user was removed", executor, then);
    if (user.value->disabled) return self->_remove(key, "the user was disabled", executor, then);
    self->_grants->effective(session->user_id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> scopes) {
      if (!scopes.ok()) return then();
      std::optional<Session> changed;
      {
        dannan::contract::Lock state(self->_mutex);
        const auto found = self->_held.find(key);
        if (found == self->_held.end()) return then();
        const bool moved = found->second.scopes != scopes.value || found->second.last_seen != self->_saved_seen[key];
        found->second.scopes = scopes.value;
        if (moved) changed = found->second;
      }
      if (!changed) return then();
      self->_calls.put_settled(kTable, key, encode(*changed), changed->version, executor, [=](store::Write written) {
        if (written.ok()) {
          dannan::contract::Lock state(self->_mutex);
          const auto found = self->_held.find(key);
          if (found != self->_held.end()) found->second.version = written.version;
          self->_saved_seen[key] = changed->last_seen;
        }
        then();
      });
    });
  });
}

void Sessions::refresh(Deadline deadline, Executor executor, Done<Status> done) {
  auto answer =
      Completion<Status>::start(deadline, executor, std::move(done), [] { return Status::failure("the sessions were not refreshed within the deadline"); });
  auto keys = std::make_shared<std::vector<std::string>>();
  {
    dannan::contract::Lock state(_mutex);
    for (const auto& [key, session] : _held) keys->push_back(key);
  }
  auto self = shared_from_this();
  in_turn<std::string>(
      keys, 0, [self, executor](const std::string& key, std::function<void()> next) { self->_refresh_one(key, executor, std::move(next)); },
      [answer] { answer->finish(Status::success()); });
}

}  // namespace lugh::session
