//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/api_client.h"

#include <stdexcept>

#include "lugh/client/claims.h"
#include "lugh/client/dpop.h"

namespace lugh::client {

namespace {

// The fault an API error code stands for (lugh/api/api_support.h, write_fault).
Fault fault_of(unsigned status, const std::string& code) {
  if (code == "not_found") return Fault::not_found;
  if (code == "changed") return Fault::conflict;
  if (code == "duplicate") return Fault::duplicate;
  if (code == "invalid" || code == "if_match_required") return Fault::invalid;
  if (code == "refused" || status == 401 || status == 403) return Fault::refused;
  return Fault::failed;
}

}  // namespace

ApiClient::ApiClient(std::string base_url, std::shared_ptr<const dannan::identity::Secret> access_token, Https& https, const dannan::contract::WallClock& wall,
                     std::shared_ptr<const dannan::identity::SigningKey> dpop_key)
    : _base(std::move(base_url)), _token(std::move(access_token)), _https(https), _wall(wall), _dpop_key(std::move(dpop_key)) {
  if (!https_target(_base)) throw std::invalid_argument("the API's base is not an https URL: " + _base);
  if (!_token) throw std::invalid_argument("an API client needs an access token");
}

void ApiClient::use_token(std::shared_ptr<const dannan::identity::Secret> access_token) {
  if (!access_token) throw std::invalid_argument("an API client needs an access token");
  _token = std::move(access_token);
}

void ApiClient::call(ApiCall call, Deadline deadline, Executor executor, Done<Outcome<ApiAnswer>> done) {
  using Answer = Outcome<ApiAnswer>;
  if (call.path.empty() || call.path.front() != '/') return answer_now(executor, std::move(done), Answer::failure(Fault::invalid, "a path begins with '/'"));
  HttpsRequest request;
  request.method = call.method;
  request.url = _base + "/api/v1" + call.path;
  request.headers.emplace_back("Accept", "application/json");
  const auto& bytes = _token->reveal();
  const std::string token(bytes.begin(), bytes.end());
  if (_dpop_key) {
    // RFC 9449 section 4.2: htu without the query.
    const auto htu = request.url.substr(0, request.url.find('?'));
    request.headers.emplace_back("Authorization", "DPoP " + token);
    request.headers.emplace_back("DPoP", dpop_proof(*_dpop_key, call.method, htu, _wall.unix_ms() / 1000, token));
  } else {
    request.headers.emplace_back("Authorization", "Bearer " + token);
  }
  if (!call.if_match.empty()) request.headers.emplace_back("If-Match", call.if_match);
  if (call.body) {
    request.content_type = "application/json";
    request.body = boost::json::serialize(*call.body);
  }
  _https.send(std::move(request), deadline, std::move(executor), [done = std::move(done)](Outcome<HttpsResponse> answered) {
    if (!answered.ok()) return done(Answer::from(answered));
    ApiAnswer out;
    out.status = answered.value.status;
    out.etag = answered.value.etag;
    if (!answered.value.body.empty()) {
      boost::system::error_code ec;
      out.body = boost::json::parse(answered.value.body, ec);
      if (ec) return done(Answer::failure(Fault::failed, "the API's answer is not JSON"));
    }
    if (out.status >= 200 && out.status < 300) return done(Answer::success(std::move(out)));
    std::string code;
    std::string message;
    if (const auto* object = out.body.if_object()) {
      if (const auto error = object->if_contains("error"); error && error->is_object()) {
        code = string_claim(error->as_object(), "code").value_or("");
        message = string_claim(error->as_object(), "message").value_or("");
      }
    }
    if (code.empty()) code = "status " + std::to_string(out.status);
    done(Answer::failure(fault_of(out.status, code), code + ": " + message));
  });
}

}  // namespace lugh::client
