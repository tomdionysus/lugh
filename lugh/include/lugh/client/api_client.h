//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <memory>
#include <optional>
#include <string>

#include "dannan/contract/time_source.h"
#include "dannan/identity/secure_memory.h"
#include "dannan/identity/signing.h"
#include "lugh/client/https.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"

// A client of a Lugh node's management API, /api/v1 (docs/api.md): a call by method and path,
// with an access token (Bearer, or DPoP with a proof by the key it is bound to, RFC 9449 section
// 7), a JSON body when it has one, and the ETag last read as If-Match for a write (Lugh refuses a
// write without one). The answer's status, JSON body and ETag; the API's errors, whose code a
// caller branches on, as Lugh's faults: not_found; changed (another wrote first) as conflict;
// duplicate; invalid (and if_match_required); refused (and 401, 403); failed otherwise.
namespace lugh::client {

struct ApiCall {
  // GET, POST, PATCH, PUT or DELETE.
  std::string method = "GET";
  // Under /api/v1, beginning with '/': "/users", "/groups/{id}/members".
  std::string path;
  std::optional<boost::json::value> body;
  // The ETag last read, or "*" to overwrite whatever is there.
  std::string if_match;
};

struct ApiAnswer {
  unsigned status = 0;
  boost::json::value body;
  std::string etag;
};

class ApiClient {
 public:
  // The node's base URL (an issuer's, as Lugh's discovery names it), and the token calls carry.
  // With `dpop_key`, the token is bound to that key and each call carries a proof by it.
  // `https` and `wall` outlive this.
  ApiClient(std::string base_url, std::shared_ptr<const dannan::identity::Secret> access_token, Https& https, const dannan::contract::WallClock& wall,
            std::shared_ptr<const dannan::identity::SigningKey> dpop_key = nullptr);

  // A new access token, when the old one is refreshed.
  void use_token(std::shared_ptr<const dannan::identity::Secret> access_token);

  void call(ApiCall call, Deadline deadline, Executor executor, Done<Outcome<ApiAnswer>> done);

 private:
  std::string _base;
  std::shared_ptr<const dannan::identity::Secret> _token;
  Https& _https;
  const dannan::contract::WallClock& _wall;
  std::shared_ptr<const dannan::identity::SigningKey> _dpop_key;
};

}  // namespace lugh::client
