//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/genesis.h"

#include "lugh/core/encoding.h"
#include "lugh/core/steps.h"

namespace lugh::authn {

Genesis::Genesis(std::shared_ptr<directory::Directory> directory, std::shared_ptr<Passwords> passwords, std::shared_ptr<EnrolmentLinks> links,
                 std::shared_ptr<audit::AuditLog> audit)
    : _directory(std::move(directory)), _passwords(std::move(passwords)), _links(std::move(links)), _audit(std::move(audit)) {}

void Genesis::run(Deadline deadline, Executor executor, Done<Outcome<Secret>> done) const {
  using Answer = Outcome<Secret>;
  auto answer = answering<Secret>(deadline, executor, std::move(done), "genesis did not finish within the deadline; it may have been partly done");
  const auto directory = _directory;
  const auto passwords = _passwords;
  const auto links = _links;
  const auto audit = _audit;
  const audit::Actor actor{"genesis", ""};
  constexpr Deadline kStep = std::chrono::seconds(30);

  directory->users(kStep, executor, [=](Outcome<std::vector<directory::User>> users) {
    if (!users.ok()) return answer->finish(Answer::from(users));
    if (!users.value.empty()) return answer->finish(Answer::failure(Fault::refused, "this cluster has had its genesis"));
    directory->groups(kStep, executor, [=](Outcome<std::vector<directory::Group>> groups) {
      if (!groups.ok()) return answer->finish(Answer::from(groups));
      if (!groups.value.empty()) return answer->finish(Answer::failure(Fault::refused, "this cluster has had its genesis"));
      directory->create_user(actor, {directory::Kind::person, kRoot, "", "Root", "", ""}, kStep, executor, [=](Outcome<directory::User> root) {
        if (!root.ok()) return answer->finish(Answer::from(root));
        directory->create_group(actor, kAdministrators, "Administer Lugh itself", kStep, executor, [=](Outcome<directory::Group> administrators) {
          if (!administrators.ok()) return answer->finish(Answer::from(administrators));
          directory->add_member(actor, administrators.value.id, root.value.id, kStep, executor, [=](Outcome<> added) {
            if (!added.ok()) return answer->finish(Answer::from(added));
            const auto raw = secure_random(kPasswordBytes);
            // Held where every step can reach it: a Secret is not copied.
            auto password = std::make_shared<Secret>(text_secret(encoding::base64url(raw)));
            passwords->set(actor, root.value, Secret(password->reveal()), kStep, executor, [=](Outcome<> set) {
              if (!set.ok()) return answer->finish(Answer::from(set));
              links->first_sign_in_allow(actor, root.value.id, kStep, executor, [=](Outcome<> allowed) {
                if (!allowed.ok()) return answer->finish(Answer::from(allowed));
                audit->record(audit::Event{"genesis", actor.id, root.value.id, {}, "root, in administrators"}, kStep, executor,
                              [answer, password](Status) { answer->finish(Answer::success(std::move(*password))); });
              });
            });
          });
        });
      });
    });
  });
}

}  // namespace lugh::authn
