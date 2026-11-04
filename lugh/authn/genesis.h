//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "lugh/audit/audit_log.h"
#include "lugh/authn/enrolment_links.h"
#include "lugh/authn/passwords.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/core/secret.h"
#include "lugh/core/task.h"
#include "lugh/directory/directory.h"
#include "lugh/scopes/grants.h"

namespace lugh::authn {

// The birth of a cluster, once in its life, as `lugh-node init` makes its first node: the user
// root, in the group administrators, which is granted every one of Lugh's own scopes, with a
// password made here at random. That password is
// the one credential Lugh is born with. There is no other: no token, no key in a file, no
// setting. It is returned to be shown once and kept nowhere but as its hash.
//
// Root is not enrolled. Their first sign-in goes from that password straight to enrolling a
// second factor, once; after that they sign in as anyone does.
class Genesis {
 public:
  static constexpr const char* kRoot = "root";
  static constexpr const char* kAdministrators = "administrators";
  // 144 bits, as 24 base64url characters.
  static constexpr std::size_t kPasswordBytes = 18;

  Genesis(std::shared_ptr<directory::Directory> directory, std::shared_ptr<Passwords> passwords, std::shared_ptr<EnrolmentLinks> links,
          std::shared_ptr<scopes::Grants> grants, std::shared_ptr<audit::AuditLog> audit);

  // Root's password. refused when the directory already has anyone in it: genesis happens
  // once. In Dannan's shape; the steps hold what they need, so the Genesis may go at once.
  void run(Deadline deadline, Executor executor, Done<Outcome<Secret>> done) const;

 private:
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<Passwords> _passwords;
  std::shared_ptr<EnrolmentLinks> _links;
  std::shared_ptr<scopes::Grants> _grants;
  std::shared_ptr<audit::AuditLog> _audit;
};

}  // namespace lugh::authn
