//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/policy.h"

#include <algorithm>

#include "lugh/core/steps.h"

namespace lugh::authn {

namespace {

constexpr std::uint8_t kFormat = 1;
// A group's policy cleared: a removal would be final, and the group may set one again.
constexpr std::uint8_t kNone = 0;

}  // namespace

std::string_view acr(Assurance assurance) {
  switch (assurance) {
    case Assurance::pwd:
      return "urn:lugh:acr:pwd";
    case Assurance::mfa:
      return "urn:lugh:acr:mfa";
    case Assurance::phr:
      return "urn:lugh:acr:phr";
  }
  return "urn:lugh:acr:pwd";
}

std::optional<Assurance> assurance_from_acr(std::string_view text) {
  for (const auto level : {Assurance::pwd, Assurance::mfa, Assurance::phr}) {
    if (acr(level) == text) return level;
  }
  return std::nullopt;
}

Policies::Policies(std::shared_ptr<store::Store> store, std::shared_ptr<directory::Directory> directory, std::shared_ptr<audit::AuditLog> audit)
    : _calls(std::move(store)), _directory(std::move(directory)), _audit(std::move(audit)) {}

namespace {

constexpr const char* kReadLate = "the policies were not read within the deadline";
constexpr const char* kChangeLate = "the policies did not answer within the deadline; the change may yet be made";
constexpr Deadline kStepDeadline = std::chrono::seconds(30);

}  // namespace

void Policies::global(Deadline deadline, Executor executor, Done<Outcome<Assurance>> done) const {
  using Answer = Outcome<Assurance>;
  auto answer = answering<Assurance>(deadline, executor, std::move(done), kReadLate);
  _read("global", executor, [answer](Outcome<std::optional<Assurance>> level) {
    if (!level.ok()) return answer->finish(Answer::from(level));
    answer->finish(Answer::success(level.value.value_or(kDefault)));
  });
}

void Policies::global_set(audit::Actor actor, Assurance level, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  _write(std::move(actor), "global", level, "global", executor, [answer](Outcome<> written) { answer->finish(std::move(written)); });
}

void Policies::group(std::string group_id, Deadline deadline, Executor executor, Done<Outcome<std::optional<Assurance>>> done) const {
  auto answer = answering<std::optional<Assurance>>(deadline, executor, std::move(done), kReadLate);
  _read("group/" + group_id, executor, [answer](Outcome<std::optional<Assurance>> level) { answer->finish(std::move(level)); });
}

void Policies::group_set(audit::Actor actor, std::string group_id, std::optional<Assurance> level, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  _directory->group(group_id, kStepDeadline, executor,
                    [self = shared_from_this(), answer, actor, group_id, level, executor](Outcome<std::optional<directory::Group>> found) {
                      if (!found.ok()) return answer->finish(Answer::from(found));
                      if (!found.value) return answer->finish(Answer::failure(Fault::not_found, "no such group"));
                      self->_write(actor, "group/" + group_id, level, group_id, executor, [answer](Outcome<> written) { answer->finish(std::move(written)); });
                    });
}

void Policies::required(std::string user_id, Deadline deadline, Executor executor, Done<Outcome<Assurance>> done) const {
  using Answer = Outcome<Assurance>;
  auto answer = answering<Assurance>(deadline, executor, std::move(done), kReadLate);
  auto self = shared_from_this();
  _read("global", executor, [=](Outcome<std::optional<Assurance>> global) {
    if (!global.ok()) return answer->finish(Answer::from(global));
    auto level = std::make_shared<Assurance>(global.value.value_or(kDefault));
    self->_directory->groups_of(user_id, kStepDeadline, executor, [=](Outcome<std::vector<std::string>> groups) {
      if (!groups.ok()) return answer->finish(Answer::from(groups));
      auto failed = std::make_shared<std::optional<Answer>>();
      in_turn<std::string>(
          std::make_shared<std::vector<std::string>>(std::move(groups.value)), 0,
          [=](const std::string& group_id, std::function<void()> next) {
            if (*failed) return next();
            self->_read("group/" + group_id, executor, [=](Outcome<std::optional<Assurance>> own) {
              if (!own.ok()) {
                *failed = Answer::from(own);
              } else if (own.value) {
                *level = std::max(*level, *own.value);
              }
              next();
            });
          },
          [=] { answer->finish(*failed ? std::move(**failed) : Answer::success(*level)); });
    });
  });
}

void Policies::_read(std::string key, Executor executor, Done<Outcome<std::optional<Assurance>>> done) const {
  using Answer = Outcome<std::optional<Assurance>>;
  _calls.get_settled(kTable, std::move(key), std::move(executor), [done = std::move(done)](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return done(Answer::from(record));
    const auto& found = record.value;
    if (!found || found->value.size() != 2 || found->value[0] != kFormat) return done(Answer::success(std::nullopt));
    const auto level = found->value[1];
    if (level < static_cast<std::uint8_t>(Assurance::pwd) || level > static_cast<std::uint8_t>(Assurance::phr)) return done(Answer::success(std::nullopt));
    done(Answer::success(static_cast<Assurance>(level)));
  });
}

void Policies::_write(audit::Actor actor, std::string key, std::optional<Assurance> level, std::string subject, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  SecureBuffer value{kFormat, level ? static_cast<std::uint8_t>(*level) : kNone};
  _calls.put_settled(kTable, std::move(key), std::move(value), std::nullopt, executor,
                     [audit = _audit, actor, level, subject = std::move(subject), executor, done = std::move(done)](store::Write written) mutable {
                       if (!written.ok()) return done(Answer::failure(directory::fault_of(written.error), written.message));
                       // A failure is logged by the audit log itself; the change has been made.
                       audit->record(audit::Event{"policy.set", actor.id, std::move(subject), actor.source, level ? std::string(acr(*level)) : "none"},
                                     kStepDeadline, executor, [done = std::move(done)](Status) { done(Answer::success()); });
                     });
}

}  // namespace lugh::authn
