//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/post.hpp>
#include <boost/json.hpp>
#include <deque>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "dannan/encoding/percent.h"
#include "dannan/identity/secure_memory.h"
#include "lugh/client/https.h"

// An HTTPS for lugh_client's tests: it keeps each request it is sent, so a test checks what an
// issuer or API would receive, and answers from a table by URL (a queue first, when one is set),
// on the caller's executor, never inline. A URL with no answer fails as an unreachable one does.
class RecordingHttps final : public lugh::client::Https {
 public:
  using Response = lugh::client::HttpsResponse;

  void send(lugh::client::HttpsRequest request, lugh::Deadline, lugh::Executor executor, lugh::Done<lugh::Outcome<Response>> done) override {
    auto answer = lugh::Outcome<Response>::failure(lugh::Fault::failed, "the connection failed");
    if (auto queue = queued.find(request.url); queue != queued.end() && !queue->second.empty()) {
      answer = queue->second.front();
      queue->second.pop_front();
    } else if (const auto found = answers.find(request.url); found != answers.end()) {
      answer = found->second;
    }
    sent.push_back(std::move(request));
    boost::asio::post(executor, [done = std::move(done), answer = std::move(answer)] { done(answer); });
  }

  static Response json(unsigned status, const boost::json::value& body, std::string etag = {}) {
    Response response;
    response.status = status;
    response.content_type = "application/json";
    response.etag = std::move(etag);
    response.body = boost::json::serialize(body);
    return response;
  }

  void answer(const std::string& url, unsigned status, const boost::json::value& body) { answers[url] = lugh::Outcome<Response>::success(json(status, body)); }
  void answer(const std::string& url, Response response) { answers[url] = lugh::Outcome<Response>::success(std::move(response)); }

  // The next answer for `url`, before the table's.
  void queue(const std::string& url, unsigned status, const boost::json::value& body) {
    queued[url].push_back(lugh::Outcome<Response>::success(json(status, body)));
  }

  std::size_t sent_to(const std::string& url) const {
    std::size_t count = 0;
    for (const auto& one : sent) count += one.url == url ? 1 : 0;
    return count;
  }

  std::string header(std::size_t index, const std::string& name) const {
    for (const auto& [key, value] : sent.at(index).headers) {
      if (key == name) return value;
    }
    return {};
  }

  std::map<std::string, lugh::Outcome<Response>> answers;
  std::map<std::string, std::deque<lugh::Outcome<Response>>> queued;
  std::vector<lugh::client::HttpsRequest> sent;
};

// A form body or query string, one value per name.
inline std::map<std::string, std::string> fields_of(std::string_view text) {
  std::map<std::string, std::string> out;
  while (!text.empty()) {
    const auto amp = text.find('&');
    const auto pair = text.substr(0, amp);
    const auto equals = pair.find('=');
    out[dannan::encoding::percent_decode(pair.substr(0, equals), dannan::encoding::Decoding::form)] =
        dannan::encoding::percent_decode(pair.substr(equals + 1), dannan::encoding::Decoding::form);
    if (amp == std::string_view::npos) break;
    text.remove_prefix(amp + 1);
  }
  return out;
}

inline std::string text_of(const dannan::identity::Secret& secret) { return std::string(secret.reveal().begin(), secret.reveal().end()); }
