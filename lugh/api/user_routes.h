//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "authn/authenticator.h"
#include "core/task.h"
#include "directory/directory.h"
#include "http/router.h"
#include "system/clock.h"

namespace lugh::api {

// /api/v1/users: the directory's people and services, their groups, their factors, and
// the enrolment links that let them in.
class UserRoutes {
 public:
  UserRoutes(std::shared_ptr<directory::Directory> directory, std::shared_ptr<authn::Factors> factors, std::shared_ptr<authn::Authenticator> authenticator,
             std::shared_ptr<authn::EnrolmentLinks> links);

  void register_routes(http::Router& router);

 private:
  Task<void> _list(http::RouteContext context) const;
  Task<void> _create(http::RouteContext context);
  Task<void> _get(http::RouteContext context) const;
  Task<void> _update(http::RouteContext context);
  Task<void> _remove(http::RouteContext context);
  Task<void> _groups(http::RouteContext context) const;
  Task<void> _factors(http::RouteContext context) const;
  Task<void> _remove_factor(http::RouteContext context);
  Task<void> _reset_factors(http::RouteContext context);
  Task<void> _enrolment(http::RouteContext context);

  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<authn::Factors> _factor_store;
  std::shared_ptr<authn::Authenticator> _authenticator;
  std::shared_ptr<authn::EnrolmentLinks> _links;
};

}  // namespace lugh::api
