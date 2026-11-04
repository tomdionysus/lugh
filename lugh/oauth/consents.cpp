//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/oauth/consents.h"

#include "lugh/core/steps.h"
#include "lugh/directory/directory.h"
#include "lugh/scopes/grants.h"
#include "lugh/scopes/scope.h"

namespace lugh::oauth {

namespace {

constexpr const char* kReadLate = "the consents were not read within the deadline";
constexpr const char* kChangeLate = "the consents did not answer within the deadline; the change may yet be made";
constexpr Deadline kStepDeadline = std::chrono::seconds(30);

}  // namespace

Consents::Consents(std::shared_ptr<store::Store> store, std::shared_ptr<audit::AuditLog> audit) : _calls(std::move(store)), _audit(std::move(audit)) {}

void Consents::scopes(std::string user_id, std::string client_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const {
  using Answer = Outcome<std::vector<std::string>>;
  auto answer = answering<std::vector<std::string>>(deadline, executor, std::move(done), kReadLate);
  _calls.get_settled(kTable, user_id + "/" + client_id, executor, [answer](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return answer->finish(Answer::from(record));
    if (!record.value) return answer->finish(Answer::success({}));
    // The same shape as a group's scope grant: a list of scopes.
    auto scopes = scopes::Grants::decode(record.value->value);
    if (!scopes) return answer->finish(Answer::failure(Fault::failed, "a consent record does not decode"));
    answer->finish(Answer::success(std::move(*scopes)));
  });
}

void Consents::grant(audit::Actor actor, std::string user_id, std::string client_id, std::vector<std::string> scopes, Deadline deadline, Executor executor,
                     Done<Outcome<>> done) {
  using Answer = Outcome<>;
  auto answer = answering<Nothing>(deadline, executor, std::move(done), kChangeLate);
  const auto key = user_id + "/" + client_id;
  auto self = shared_from_this();
  _calls.get_settled(kTable, key, executor, [=](Outcome<std::optional<store::Record>> record) {
    if (!record.ok()) return answer->finish(Answer::from(record));
    std::vector<std::string> all = scopes;
    std::uint64_t version = 0;
    if (record.value) {
      auto held = scopes::Grants::decode(record.value->value);
      if (!held) return answer->finish(Answer::failure(Fault::failed, "a consent record does not decode"));
      all.insert(all.end(), held->begin(), held->end());
      version = record.value->version;
    }
    all = scopes::united(std::move(all));
    self->_calls.put_settled(kTable, key, scopes::Grants::encode(all), version, executor, [=](store::Write written) {
      if (!written.ok()) return answer->finish(Answer::failure(directory::fault_of(written.error), written.message));
      self->_audit->record(audit::Event{"consent.grant", actor.id, client_id, actor.source, scopes::join(scopes)}, kStepDeadline, executor,
                           [answer](Status) { answer->finish(Answer::success()); });
    });
  });
}

}  // namespace lugh::oauth
