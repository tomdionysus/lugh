//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/api/key_routes.h"

#include "lugh/api/api_support.h"
#include "lugh/api/scopes.h"

namespace lugh::api {

namespace {

boost::json::object key_json(const tokens::KeyInfo& key) {
  boost::json::object out;
  out["kid"] = key.kid;
  out["algorithm"] = dannan::identity::algorithm_name(key.algorithm);
  out["created_at"] = timestamp(key.created);
  out["signing_from"] = timestamp(key.active_from);
  out["retired_at"] = key.retired_at == 0 ? boost::json::value(nullptr) : boost::json::value(timestamp(key.retired_at));
  return out;
}

}  // namespace

KeyRoutes::KeyRoutes(std::shared_ptr<tokens::SigningKeys> keys) : _keys(std::move(keys)) {}

void KeyRoutes::register_routes(http::Router& router) {
  using http::verb;
  router.add(verb::get, "/api/v1/keys", kDirectoryRead, [keys = _keys](http::RouteContext context) {
    boost::json::array list;
    for (const auto& key : keys->keys()) list.push_back(key_json(key));
    answer_json(context, http::status::ok, boost::json::object{{"keys", std::move(list)}});
  });
  router.add(verb::post, "/api/v1/keys/rotate", kKeysWrite, [keys = _keys](http::RouteContext context) {
    const auto body = body_object(context, {"algorithm"});
    if (!body) return context.done();
    const auto algorithm = http::string_field(*body, "algorithm");
    if (!algorithm || (*algorithm != "ES256" && *algorithm != "EdDSA")) {
      http::write_error(context.response, http::status::bad_request, "invalid", "algorithm is ES256 or EdDSA");
      return context.done();
    }
    const auto chosen = *algorithm == "ES256" ? tokens::SigningAlgorithm::es256 : tokens::SigningAlgorithm::ed25519;
    keys->rotate(actor_of(context), chosen, kRouteDeadline, context.executor, [context](Outcome<tokens::KeyInfo> made) {
      if (!made.ok()) return answer_fault(context, made);
      answer_json(context, http::status::created, key_json(made.value));
    });
  });
}

}  // namespace lugh::api
