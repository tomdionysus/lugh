//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/http/outbound.h"

namespace lugh::http {

HttpsOutbound::HttpsOutbound(net::io_context& io_context, const std::string& ca_path) : _https(io_context, ca_path) {}

void HttpsOutbound::post_form(std::string url, std::string body, Deadline deadline, Executor executor, Done<Outcome<unsigned>> done) {
  client::HttpsRequest request;
  request.method = "POST";
  request.url = std::move(url);
  request.content_type = "application/x-www-form-urlencoded";
  request.body = std::move(body);
  _https.send(std::move(request), deadline, std::move(executor), [done = std::move(done)](Outcome<client::HttpsResponse> answered) {
    if (!answered.ok()) return done(Outcome<unsigned>::from(answered));
    done(Outcome<unsigned>::success(answered.value.status));
  });
}

}  // namespace lugh::http
