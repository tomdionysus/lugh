//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "audit/audit_log.h"
#include "http/router.h"

namespace lugh::api {

// /api/v1/audit: the audit log, a page at a time, and a walk of its whole chain.
class AuditRoutes {
 public:
  static constexpr std::uint64_t kDefaultPage = 100;
  static constexpr std::uint64_t kMostPage = 1000;

  explicit AuditRoutes(std::shared_ptr<audit::AuditLog> audit);

  void register_routes(http::Router& router);

 private:
  std::shared_ptr<audit::AuditLog> _audit;
};

}  // namespace lugh::api
