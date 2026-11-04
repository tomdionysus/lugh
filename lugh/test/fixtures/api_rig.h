//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "lugh/api/audit_routes.h"
#include "lugh/api/group_routes.h"
#include "lugh/api/policy_routes.h"
#include "lugh/api/scope_routes.h"
#include "lugh/api/scopes.h"
#include "lugh/api/user_routes.h"
#include "lugh/test/fixtures/authn_rig.h"
#include "lugh/test/fixtures/fixed_callers.h"
#include "lugh/test/fixtures/route_call.h"

// The whole of /api/v1 over AuthnRig, behind a router where the token kToken is an
// administrator holding every scope and "reader" holds directory.read alone, as P6's
// sessions and tokens will resolve them.
class ApiRig : public AuthnRig {
 public:
  static constexpr const char* kToken = "administrator";
  static constexpr const char* kAdministrator = "u-administrator";

  struct Answer {
    unsigned status = 0;
    boost::json::value body;
    std::shared_ptr<lugh::http::HttpResponse> response;

    std::string header(lugh::http::field name) const { return std::string(response->base()[name]); }
    std::string error() const { return std::string(body.at("error").at("code").as_string()); }
  };

  ApiRig()
      : callers(make_callers()),
        router(std::make_shared<lugh::http::Router>(io.get_executor(),
                                                    std::make_shared<lugh::http::Throttle>(time, lugh::http::RateLimits{{1000, 1000}, {1000, 1000}}), callers)),
        users(directory, factors, authenticator, links),
        groups(directory),
        policy_routes(policies, directory),
        scope_routes(grants),
        audit_routes(audit) {
    users.register_routes(*router);
    groups.register_routes(*router);
    policy_routes.register_routes(*router);
    scope_routes.register_routes(*router);
    audit_routes.register_routes(*router);
  }

  static std::shared_ptr<FixedCallers> make_callers() {
    auto made = std::make_shared<FixedCallers>();
    made->add(kToken, lugh::http::Caller{lugh::http::Caller::Kind::user, kAdministrator, lugh::api::all_scopes()});
    made->add("reader", lugh::http::Caller{lugh::http::Caller::Kind::user, "u-reader", {lugh::api::kDirectoryRead}});
    return made;
  }

  // As the administrator, unless `authorization` says otherwise ("" for none).
  Answer request(lugh::http::verb method, const std::string& target, const std::string& body = "",
                 std::vector<std::pair<lugh::http::field, std::string>> headers = {}, std::optional<std::string> authorization = std::nullopt) {
    const auto credential = authorization.value_or(std::string("Bearer ") + kToken);
    if (!credential.empty()) headers.emplace_back(lugh::http::field::authorization, credential);
    const auto result = call(io, router->middleware("/api"), method, target, "192.0.2.50", body, headers);
    EXPECT_TRUE(result.answered) << target;

    Answer answer;
    answer.status = static_cast<unsigned>(result.response->result_int());
    answer.response = result.response;
    if (!result.response->body().empty()) answer.body = boost::json::parse(result.response->body());
    return answer;
  }

  Answer get(const std::string& target) { return request(lugh::http::verb::get, target); }
  Answer post(const std::string& target, const std::string& body) { return request(lugh::http::verb::post, target, body); }

  // A user made through the API: its ID.
  std::string made_user(const std::string& name) {
    const auto made = post("/api/v1/users", R"({"name":")" + name + R"(","email":")" + name + R"(@example.com"})");
    EXPECT_EQ(made.status, 201u);
    return std::string(made.body.at("id").as_string());
  }

  // Declared first: the router's handlers run on it.
  boost::asio::io_context io;
  std::shared_ptr<FixedCallers> callers;
  std::shared_ptr<lugh::http::Router> router;
  lugh::api::UserRoutes users;
  lugh::api::GroupRoutes groups;
  lugh::api::PolicyRoutes policy_routes;
  lugh::api::ScopeRoutes scope_routes;
  lugh::api::AuditRoutes audit_routes;
};
