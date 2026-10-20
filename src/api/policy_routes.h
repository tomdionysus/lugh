#pragma once

#include <memory>

#include "authn/policy.h"
#include "core/task.h"
#include "directory/directory.h"
#include "http/router.h"

namespace lugh::api {

// /api/v1/policies: the assurance level each person must reach, globally and per group.
// A level is a setting, written whole with PUT, so it takes no If-Match.
class PolicyRoutes {
 public:
  PolicyRoutes(std::shared_ptr<authn::Policies> policies, std::shared_ptr<directory::Directory> directory);

  void register_routes(http::Router& router);

 private:
  Task<void> _get(http::RouteContext context) const;
  Task<void> _set_global(http::RouteContext context);
  Task<void> _set_group(http::RouteContext context);

  std::shared_ptr<authn::Policies> _policies;
  std::shared_ptr<directory::Directory> _directory;
};

}  // namespace lugh::api
