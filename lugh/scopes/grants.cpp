//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/scopes/grants.h"

#include "lugh/core/codec.h"
#include "lugh/core/steps.h"
#include "lugh/scopes/scope.h"

namespace lugh::scopes {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr const char* kReadLate = "the scope grants were not read within the deadline";
constexpr const char* kChangeLate = "the scope grants did not answer within the deadline; the change may yet be made";
constexpr Deadline kStepDeadline = std::chrono::seconds(30);

}  // namespace

Grants::Grants(std::shared_ptr<store::Store> store, std::shared_ptr<directory::Directory> directory, std::shared_ptr<apps::Apps> apps,
               std::shared_ptr<audit::AuditLog> audit)
    : _calls(std::move(store)), _directory(std::move(directory)), _apps(std::move(apps)), _audit(std::move(audit)) {}

SecureBuffer Grants::encode(const std::vector<std::string>& scopes) {
  SecureWriter writer;
  writer.u8(kFormat);
  writer.u32(static_cast<std::uint32_t>(scopes.size()));
  for (const auto& scope : scopes) writer.string(scope);
  return writer.take();
}

std::optional<std::vector<std::string>> Grants::decode(std::span<const unsigned char> value) {
  return decode_whole<std::vector<std::string>>(value, [](dannan::net::Reader& reader) -> std::optional<std::vector<std::string>> {
    if (reader.u8() != kFormat) return std::nullopt;
    const auto count = reader.u32();
    if (count > kMostScopes) return std::nullopt;
    std::vector<std::string> out;
    out.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) out.push_back(reader.string(kMostScopeBytes));
    return out;
  });
}

void Grants::_read(std::string group_id, Executor executor, Done<Outcome<Granted>> done) const {
  using Answer = Outcome<Granted>;
  _calls.get_settled(kTable, std::move(group_id), std::move(executor), [done = std::move(done)](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return done(Answer::from(record));
    if (!record.value) return done(Answer::success({}));
    auto scopes = decode(record.value->value);
    // A record that does not decode grants nothing, and says so: it is never read as some
    // other set.
    if (!scopes) return done(Answer::failure(Fault::failed, "a scope grant record does not decode"));
    done(Answer::success(Granted{std::move(*scopes), record.value->version}));
  });
}

void Grants::group(std::string group_id, Deadline deadline, Executor executor, Done<Outcome<Granted>> done) const {
  using Answer = Outcome<Granted>;
  auto answer = answering<Granted>(deadline, executor, std::move(done), kReadLate);
  auto self = shared_from_this();
  _directory->group(group_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::Group>> found) {
    if (!found.ok()) return answer->finish(Answer::from(found));
    if (!found.value) return answer->finish(Answer::failure(Fault::not_found, "no such group"));
    self->_read(group_id, executor, [answer](Answer granted) { answer->finish(std::move(granted)); });
  });
}

void Grants::group_set(audit::Actor actor, std::string group_id, std::vector<std::string> scopes, std::optional<std::uint64_t> expected, Deadline deadline,
                       Executor executor, Done<Outcome<Granted>> done) {
  using Answer = Outcome<Granted>;
  auto answer = answering<Granted>(deadline, executor, std::move(done), kChangeLate);
  if (scopes.size() > kMostScopes) return answer->finish(Answer::failure(Fault::invalid, "a group grants at most 256 scopes"));
  for (const auto& scope : scopes) {
    const auto kind = grantable(scope);
    if (!kind.ok()) return answer->finish(Answer::from(kind));
  }
  auto sorted = std::make_shared<std::vector<std::string>>(united(std::move(scopes)));

  auto self = shared_from_this();
  _apps->prefixes(kStepDeadline, executor, [=](Outcome<std::vector<std::string>> registered) {
    if (!registered.ok()) return answer->finish(Answer::from(registered));
    if (const auto ok = apps::Apps::references_ok(registered.value, "", *sorted, {}); !ok.ok()) return answer->finish(Answer::from(ok));
    self->_directory->group(group_id, kStepDeadline, executor, [=](Outcome<std::optional<directory::Group>> found) {
      if (!found.ok()) return answer->finish(Answer::from(found));
      if (!found.value) return answer->finish(Answer::failure(Fault::not_found, "no such group"));
      self->_read(group_id, executor, [=](Answer current) {
        if (!current.ok()) return answer->finish(std::move(current));
        if (expected && *expected != current.value.version)
          return answer->finish(Answer::failure(Fault::conflict, "the group's scopes have changed since they were read"));
        if (current.value.version != 0 && current.value.scopes == *sorted) return answer->finish(std::move(current));
        self->_calls.put_settled(kTable, group_id, encode(*sorted), current.value.version, executor, [=](store::Write written) {
          if (!written.ok()) return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
          Granted made{*sorted, written.version};
          // A failure is logged by the audit log itself; the change has been made.
          self->_audit->record(audit::Event{"scopes.set", actor.id, group_id, actor.source, join(*sorted)}, kStepDeadline, executor,
                               [answer, made](Status) { answer->finish(Answer::success(made)); });
        });
      });
    });
  });
}

void Grants::effective(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const {
  using Answer = Outcome<std::vector<std::string>>;
  auto answer = answering<std::vector<std::string>>(deadline, executor, std::move(done), kReadLate);
  auto self = shared_from_this();
  _directory->groups_of(user_id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> groups) {
    if (!groups.ok()) return answer->finish(Answer::from(groups));
    auto all = std::make_shared<std::vector<std::string>>();
    auto failed = std::make_shared<std::optional<Answer>>();
    in_turn<std::string>(
        std::make_shared<std::vector<std::string>>(std::move(groups.value)), 0,
        [=](const std::string& group_id, std::function<void()> next) {
          if (*failed) return next();
          self->_read(group_id, executor, [=](Outcome<Granted> granted) {
            if (!granted.ok()) {
              *failed = Answer::from(granted);
            } else {
              all->insert(all->end(), granted.value.scopes.begin(), granted.value.scopes.end());
            }
            next();
          });
        },
        [=] { answer->finish(*failed ? std::move(**failed) : Answer::success(united(std::move(*all)))); });
  });
}

}  // namespace lugh::scopes
