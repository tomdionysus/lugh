//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/testing.h"

#include <boost/asio/post.hpp>
#include <stdexcept>

#include "lugh/client/jose.h"

namespace lugh::client::testing {

void FakeHttps::send(HttpsRequest request, Deadline, Executor executor, Done<Outcome<Response>> done) {
  auto answer = Outcome<Response>::failure(Fault::failed, "the connection failed");
  {
    dannan::contract::Lock lock(_mutex);
    _sent.push_back(request);
    if (_holding.contains(request.url)) {
      _held.push_back({std::move(executor), std::move(done)});
      return;
    }
    if (auto queue = _queued.find(request.url); queue != _queued.end() && !queue->second.empty()) {
      answer = queue->second.front();
      queue->second.pop_front();
    } else if (const auto found = _answers.find(request.url); found != _answers.end()) {
      answer = found->second;
    }
  }
  boost::asio::post(executor, [done = std::move(done), answer = std::move(answer)] { done(answer); });
}

FakeHttps::Response FakeHttps::json(unsigned status, const boost::json::value& body, std::string etag) {
  Response response;
  response.status = status;
  response.content_type = "application/json";
  response.etag = std::move(etag);
  response.body = boost::json::serialize(body);
  return response;
}

void FakeHttps::answer(const std::string& url, Outcome<Response> outcome) {
  dannan::contract::Lock lock(_mutex);
  _answers[url] = std::move(outcome);
}

void FakeHttps::forget_answers() {
  dannan::contract::Lock lock(_mutex);
  _answers.clear();
}

void FakeHttps::queue(const std::string& url, unsigned status, const boost::json::value& body) {
  dannan::contract::Lock lock(_mutex);
  _queued[url].push_back(Outcome<Response>::success(json(status, body)));
}

void FakeHttps::hold(const std::string& url) {
  dannan::contract::Lock lock(_mutex);
  _holding.insert(url);
}

void FakeHttps::let_go(const std::string& url) {
  dannan::contract::Lock lock(_mutex);
  _holding.erase(url);
}

std::size_t FakeHttps::held() const {
  dannan::contract::Lock lock(_mutex);
  return _held.size();
}

void FakeHttps::release(Outcome<Response> answer) {
  Held one;
  {
    dannan::contract::Lock lock(_mutex);
    if (_held.empty()) throw std::out_of_range("no request is held");
    one = std::move(_held.front());
    _held.pop_front();
  }
  boost::asio::post(one.executor, [done = std::move(one.done), answer = std::move(answer)] { done(answer); });
}

std::vector<HttpsRequest> FakeHttps::sent() const {
  dannan::contract::Lock lock(_mutex);
  return _sent;
}

std::size_t FakeHttps::sent_to(const std::string& url) const {
  dannan::contract::Lock lock(_mutex);
  std::size_t count = 0;
  for (const auto& one : _sent) count += one.url == url ? 1 : 0;
  return count;
}

std::string FakeHttps::header(std::size_t index, const std::string& name) const {
  dannan::contract::Lock lock(_mutex);
  for (const auto& [key, value] : _sent.at(index).headers) {
    if (key == name) return value;
  }
  return {};
}

std::string sign_access_token(const dannan::identity::SigningKey& key, const std::string& kid, const boost::json::object& claims) {
  return jws_sign(key, kid, "at+jwt", claims);
}

std::string sign_id_token(const dannan::identity::SigningKey& key, const std::string& kid, const boost::json::object& claims) {
  return jws_sign(key, kid, "JWT", claims);
}

boost::json::object jwks(const dannan::identity::SigningKey& key, const std::string& kid) {
  boost::json::array keys;
  keys.push_back(*public_jwk({kid, key.algorithm(), key.public_key()}));
  return {{"keys", std::move(keys)}};
}

}  // namespace lugh::client::testing
