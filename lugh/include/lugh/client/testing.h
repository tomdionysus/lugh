//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <cstddef>
#include <deque>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "dannan/contract/thread_safety.h"
#include "dannan/identity/signing.h"
#include "lugh/client/https.h"

// For a relying party's tests: tokens signed as a Lugh issuer signs them, the keys a Verifier
// needs to check them, and an HTTPS that answers as a test says, so a consumer's tests prove its
// verification and its calls to an issuer with real tokens and no Lugh internals. A test holds the
// issuer's private key; nothing here is for production.
namespace lugh::client::testing {

// An HTTPS for tests: it keeps each request it is sent, so a test checks what an issuer or API
// would receive, and answers from a table by URL (a queue first, when one is set), on the caller's
// executor, never inline. A URL with no answer fails as an unreachable one does. A URL the test
// holds is not answered until the test answers it, so a test sees what happens while a call is
// outstanding, and in what order answers arrive. Thread-safe: a test may answer and read from its
// own thread while the code under test calls from the io context's.
class FakeHttps final : public Https {
 public:
  using Response = HttpsResponse;

  void send(HttpsRequest request, Deadline deadline, Executor executor, Done<Outcome<Response>> done) override;

  static Response json(unsigned status, const boost::json::value& body, std::string etag = {});

  void answer(const std::string& url, unsigned status, const boost::json::value& body) { answer(url, Outcome<Response>::success(json(status, body))); }
  void answer(const std::string& url, Response response) { answer(url, Outcome<Response>::success(std::move(response))); }
  void answer(const std::string& url, Outcome<Response> outcome);
  // Every answer in the table gone, so each URL fails as an unreachable one does.
  void forget_answers();
  // The next answer for `url`, before the table's.
  void queue(const std::string& url, unsigned status, const boost::json::value& body);

  // Requests to `url` wait for release() from now on, until let_go(url).
  void hold(const std::string& url);
  void let_go(const std::string& url);
  // How many requests are held.
  std::size_t held() const;
  // Answers the oldest held request with `answer`, posted to its executor. Throws
  // std::out_of_range when none is held.
  void release(Outcome<Response> answer);

  // Every request sent so far, in order.
  std::vector<HttpsRequest> sent() const;
  std::size_t sent_to(const std::string& url) const;
  // A header of the request sent `index`th, or empty.
  std::string header(std::size_t index, const std::string& name) const;

 private:
  struct Held {
    Executor executor;
    Done<Outcome<Response>> done;
  };

  mutable dannan::contract::Mutex _mutex;
  std::map<std::string, Outcome<Response>> _answers DANNAN_GUARDED_BY(_mutex);
  std::map<std::string, std::deque<Outcome<Response>>> _queued DANNAN_GUARDED_BY(_mutex);
  std::set<std::string> _holding DANNAN_GUARDED_BY(_mutex);
  std::deque<Held> _held DANNAN_GUARDED_BY(_mutex);
  std::vector<HttpsRequest> _sent DANNAN_GUARDED_BY(_mutex);
};

// An access token signed by `key` under `kid`, as Lugh signs one: typ at+jwt, ES256 or EdDSA by
// the key, `claims` as given (iss, sub, aud, client_id, exp, jti and the rest are the test's).
std::string sign_access_token(const dannan::identity::SigningKey& key, const std::string& kid, const boost::json::object& claims);

// An ID token, likewise: typ JWT.
std::string sign_id_token(const dannan::identity::SigningKey& key, const std::string& kid, const boost::json::object& claims);

// A JWKS holding `key`'s public part under `kid`, ready for Verifier::set_keys.
boost::json::object jwks(const dannan::identity::SigningKey& key, const std::string& kid);

}  // namespace lugh::client::testing
