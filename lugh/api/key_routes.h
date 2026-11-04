//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>

#include "lugh/http/router.h"
#include "lugh/tokens/signing_keys.h"

namespace lugh::api {

// /api/v1/keys: the token signing keys, never their private parts, and rotating one.
class KeyRoutes {
 public:
  explicit KeyRoutes(std::shared_ptr<tokens::SigningKeys> keys);

  void register_routes(http::Router& router);

 private:
  std::shared_ptr<tokens::SigningKeys> _keys;
};

}  // namespace lugh::api
