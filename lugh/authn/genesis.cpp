//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/authn/genesis.h"

#include "lugh/core/encoding.h"

namespace lugh::authn {

Genesis::Genesis(std::shared_ptr<directory::Directory> directory, std::shared_ptr<Passwords> passwords, std::shared_ptr<EnrolmentLinks> links,
                 std::shared_ptr<audit::AuditLog> audit)
    : _directory(std::move(directory)), _passwords(std::move(passwords)), _links(std::move(links)), _audit(std::move(audit)) {}

Task<Outcome<Secret>> Genesis::run() {
  using Answer = Outcome<Secret>;
  if (!(co_await _directory->users()).empty() || !(co_await _directory->groups()).empty()) {
    co_return Answer::failure(Fault::refused, "this cluster has had its genesis");
  }

  const audit::Actor actor{"genesis", ""};
  const auto root = co_await _directory->create_user(actor, {directory::Kind::person, kRoot, "", "Root"});
  if (!root.ok()) co_return Answer::from(root);
  const auto administrators = co_await _directory->create_group(actor, kAdministrators, "Administer Lugh itself");
  if (!administrators.ok()) co_return Answer::from(administrators);
  if (const auto added = co_await _directory->add_member(actor, administrators.value.id, root.value.id); !added.ok()) co_return Answer::from(added);

  const auto raw = secure_random(kPasswordBytes);
  auto password = text_secret(encoding::base64url(raw));

  if (const auto set = co_await _passwords->set(actor, root.value, Secret(password.reveal())); !set.ok()) co_return Answer::from(set);
  if (const auto allowed = co_await _links->first_sign_in_allow(actor, root.value.id); !allowed.ok()) co_return Answer::from(allowed);

  co_await _audit->record(audit::Event{"genesis", actor.id, root.value.id, {}, "root, in administrators"});
  co_return Answer::success(std::move(password));
}

}  // namespace lugh::authn
