//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/key_source.h"

#include <algorithm>
#include <boost/asio/post.hpp>
#include <boost/json.hpp>
#include <variant>

namespace lugh::client {

namespace {

// The body of a 200 answer as a JSON object, or why not.
std::variant<boost::json::object, std::string> json_answer(const Outcome<HttpsResponse>& answered, const std::string& what) {
  if (!answered.ok()) return what + ": " + answered.message;
  if (answered.value.status != 200) return what + " answered " + std::to_string(answered.value.status);
  boost::system::error_code ec;
  auto parsed = boost::json::parse(answered.value.body, ec);
  if (ec || !parsed.is_object()) return what + " is not a JSON object";
  return std::move(parsed.as_object());
}

}  // namespace

std::shared_ptr<HttpsKeySource> HttpsKeySource::make(Verifier& verifier, Https& https, Executor executor, const dannan::contract::TimeSource& time,
                                                     Settings settings) {
  return std::shared_ptr<HttpsKeySource>(new HttpsKeySource(verifier, https, std::move(executor), time, settings));
}

HttpsKeySource::HttpsKeySource(Verifier& verifier, Https& https, Executor executor, const dannan::contract::TimeSource& time, Settings settings)
    : _verifier(verifier), _https(https), _strand(boost::asio::make_strand(std::move(executor))), _time(time), _settings(settings), _timer(_strand) {
  dannan::contract::Lock lock(_mutex);
  for (const auto& issuer : _verifier.issuers()) {
    Issuer entry;
    entry.status.issuer = issuer;
    _issuers.push_back(std::move(entry));
  }
}

void HttpsKeySource::start() {
  {
    dannan::contract::Lock lock(_mutex);
    _running = true;
    for (auto& issuer : _issuers) issuer.due = _time.now();
  }
  _verifier.on_missing_keys([weak = weak_from_this()](const std::string& issuer) {
    if (const auto self = weak.lock()) boost::asio::post(self->_strand, [self, issuer] { self->_missing(issuer); });
  });
  boost::asio::post(_strand, [self = shared_from_this()] { self->_tick(); });
}

void HttpsKeySource::stop() {
  {
    dannan::contract::Lock lock(_mutex);
    _running = false;
  }
  _verifier.on_missing_keys(nullptr);
  boost::asio::post(_strand, [self = shared_from_this()] { self->_timer.cancel(); });
}

void HttpsKeySource::refresh_now() {
  {
    dannan::contract::Lock lock(_mutex);
    for (auto& issuer : _issuers) issuer.due = _time.now();
  }
  boost::asio::post(_strand, [self = shared_from_this()] { self->_tick(); });
}

std::vector<HttpsKeySource::IssuerStatus> HttpsKeySource::status() const {
  dannan::contract::Lock lock(_mutex);
  std::vector<IssuerStatus> out;
  for (const auto& issuer : _issuers) out.push_back(issuer.status);
  return out;
}

void HttpsKeySource::_tick() {
  std::vector<std::size_t> due;
  {
    dannan::contract::Lock lock(_mutex);
    if (!_running) return;
    const auto now = _time.now();
    for (std::size_t i = 0; i < _issuers.size(); ++i) {
      auto& issuer = _issuers[i];
      if (issuer.in_flight || now < issuer.due) continue;
      issuer.in_flight = true;
      issuer.attempted = true;
      issuer.last_attempt = now;
      due.push_back(i);
    }
  }
  for (const auto index : due) _fetch(index);
  _arm();
}

void HttpsKeySource::_arm() {
  std::chrono::milliseconds remaining{0};
  {
    dannan::contract::Lock lock(_mutex);
    if (!_running) return;
    const auto now = _time.now();
    bool any = false;
    dannan::contract::TimePoint next{};
    for (const auto& issuer : _issuers) {
      if (issuer.in_flight) continue;
      if (!any || issuer.due < next) next = issuer.due;
      any = true;
    }
    if (!any) return;
    remaining = std::max(std::chrono::ceil<std::chrono::milliseconds>(next - now), std::chrono::milliseconds(1));
  }
  _timer.expires_after(_time.wake_within(remaining));
  _timer.async_wait([weak = weak_from_this()](const boost::system::error_code& ec) {
    if (ec) return;
    if (const auto self = weak.lock()) self->_tick();
  });
}

void HttpsKeySource::_fetch(std::size_t index) {
  std::string issuer;
  {
    dannan::contract::Lock lock(_mutex);
    issuer = _issuers[index].status.issuer;
  }
  HttpsRequest discovery;
  discovery.url = issuer + "/.well-known/openid-configuration";
  discovery.headers = {{"Accept", "application/json"}};
  _https.send(std::move(discovery), _settings.fetch_deadline, _strand, [self = shared_from_this(), index, issuer](Outcome<HttpsResponse> answered) {
    auto document = json_answer(answered, "the discovery document");
    if (const auto* why = std::get_if<std::string>(&document)) return self->_fetched(index, *why, 0);
    const auto& metadata = std::get<boost::json::object>(document);
    const auto said = metadata.if_contains("issuer");
    if (!said || !said->is_string() || said->as_string() != issuer) return self->_fetched(index, "the discovery document names another issuer", 0);
    const auto jwks_uri = metadata.if_contains("jwks_uri");
    if (!jwks_uri || !jwks_uri->is_string() || !https_target(jwks_uri->as_string())) {
      return self->_fetched(index, "the discovery document has no https jwks_uri", 0);
    }
    HttpsRequest keys;
    keys.url = std::string(jwks_uri->as_string());
    keys.headers = {{"Accept", "application/json"}};
    self->_https.send(std::move(keys), self->_settings.fetch_deadline, self->_strand, [self, index, issuer](Outcome<HttpsResponse> fetched) {
      auto jwks = json_answer(fetched, "the JWKS");
      if (const auto* why = std::get_if<std::string>(&jwks)) return self->_fetched(index, *why, 0);
      try {
        const auto taken = self->_verifier.set_keys(issuer, std::get<boost::json::object>(jwks));
        self->_fetched(index, {}, taken);
      } catch (const std::exception& refused) {
        self->_fetched(index, refused.what(), 0);
      }
    });
  });
}

void HttpsKeySource::_fetched(std::size_t index, std::string error, std::size_t keys) {
  {
    dannan::contract::Lock lock(_mutex);
    auto& issuer = _issuers[index];
    issuer.in_flight = false;
    const auto now = _time.now();
    if (error.empty()) {
      issuer.status.state = State::fresh;
      issuer.status.keys = keys;
      issuer.status.failures = 0;
      issuer.status.last_error.clear();
      issuer.due = now + _settings.refresh;
    } else {
      ++issuer.status.failures;
      issuer.status.last_error = std::move(error);
      // The keys held stay, so an issuer that had them is stale, not without.
      if (issuer.status.state == State::fresh) issuer.status.state = State::stale;
      auto backoff = _settings.first_backoff;
      for (std::uint32_t i = 1; i < issuer.status.failures && backoff < _settings.most_backoff; ++i) backoff *= 2;
      issuer.due = now + std::min(backoff, _settings.most_backoff);
    }
  }
  _arm();
}

void HttpsKeySource::_missing(const std::string& name) {
  {
    dannan::contract::Lock lock(_mutex);
    if (!_running) return;
    const auto found = std::find_if(_issuers.begin(), _issuers.end(), [&](const Issuer& issuer) { return issuer.status.issuer == name; });
    if (found == _issuers.end() || found->in_flight) return;
    // A failing issuer keeps its backoff: a stream of refused tokens does not hurry it.
    if (found->status.failures > 0) return;
    const auto now = _time.now();
    if (found->attempted && now - found->last_attempt < _settings.missing_gap) return;
    found->due = now;
  }
  _tick();
}

}  // namespace lugh::client
