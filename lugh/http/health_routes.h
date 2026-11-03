//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include "http/router.h"

namespace lugh::http {

// GET /health and GET /ready: open, always JSON, and about the service alone. They say that
// it is up and nothing else: no version, no uptime, nothing a scanner can use. systemd, a
// load balancer and a person with curl ask them. Readiness grows a meaning when the store
// and the cluster arrive.
class HealthRoutes {
 public:
  void register_routes(Router& router);
};

}  // namespace lugh::http
