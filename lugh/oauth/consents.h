//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "lugh/audit/audit_log.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/store/store.h"
#include "lugh/store/store_calls.h"

namespace lugh::oauth {

// What a person has let a third-party application have, so they are asked once (docs/
// architecture.md, "Rules": first-party applications skip consent). In the `consents` table,
// keyed "<user>/<client_id>"; never removed, since a removal is final and the person may
// consent again: withdrawn, it is written empty. Made with std::make_shared.
class Consents : public std::enable_shared_from_this<Consents> {
 public:
  static constexpr const char* kTable = "consents";

  Consents(std::shared_ptr<store::Store> store, std::shared_ptr<audit::AuditLog> audit);

  // The scopes consented to; empty when none ever were.
  void scopes(std::string user_id, std::string client_id, Deadline deadline, Executor executor, Done<Outcome<std::vector<std::string>>> done) const;

  // Adds `scopes` to what the person has consented to for the client.
  void grant(audit::Actor actor, std::string user_id, std::string client_id, std::vector<std::string> scopes, Deadline deadline, Executor executor,
             Done<Outcome<>> done);

 private:
  store::StoreCalls _calls;
  std::shared_ptr<audit::AuditLog> _audit;
};

}  // namespace lugh::oauth
