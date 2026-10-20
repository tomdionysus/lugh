#include "api/audit_routes.h"

#include "api/api_support.h"
#include "api/representations.h"
#include "api/scopes.h"

namespace lugh::api {

AuditRoutes::AuditRoutes(std::shared_ptr<audit::AuditLog> audit) : _audit(std::move(audit)) {}

void AuditRoutes::register_routes(http::Router& router) {
  // ?from=<sequence>&limit=<count>; `next` is where the following page starts, null at the
  // end.
  router.add(http::verb::get, "/api/v1/audit", kAuditRead, [audit = _audit](http::RouteContext context) -> Task<void> {
    std::uint64_t from = 1;
    std::uint64_t limit = kDefaultPage;
    if (!number_query(context, "from", 1, UINT64_MAX / 2, from) || !number_query(context, "limit", 1, kMostPage, limit)) {
      context.done();
      co_return;
    }

    boost::json::array entries;
    const auto page = co_await audit->entries(from, limit);
    for (const auto& entry : page) entries.push_back(entry_json(entry));
    boost::json::object body;
    body["entries"] = std::move(entries);
    const auto next = page.empty() ? from : page.back().sequence + 1;
    if (next <= audit->size()) {
      body["next"] = next;
    } else {
      body["next"] = nullptr;
    }
    http::write_json(context.response, http::status::ok, body);
    context.done();
  });

  router.add(http::verb::get, "/api/v1/audit/verify", kAuditRead, [audit = _audit](http::RouteContext context) -> Task<void> {
    const auto verified = co_await audit->verify();
    boost::json::object body;
    body["intact"] = verified.ok;
    if (verified.ok) {
      body["entries"] = verified.value;
    } else {
      body["problem"] = verified.error;
    }
    http::write_json(context.response, http::status::ok, body);
    context.done();
  });
}

}  // namespace lugh::api
