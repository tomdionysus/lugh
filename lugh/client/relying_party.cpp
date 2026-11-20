//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/relying_party.h"

#include <algorithm>
#include <boost/asio/post.hpp>
#include <limits>
#include <stdexcept>

#include "lugh/client/discovery.h"

namespace lugh::client {

namespace {

using namespace std::chrono_literals;
using Method = ClientIdentity::Method;

// From 5 s to 5 min, never parked: a service never gives up on its token, as nothing else signs
// it in. Dannan's own never-parking policy (0.10.0), which this was written by hand before.
const dannan::sched::RetryPolicy kRetry = dannan::sched::RetryPolicy::unbounded(5s, 5min);

bool b64token_char(char c) {
  return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '/';
}

const RelyingParty::Settings& checked(const RelyingParty::Settings& settings) {
  if (settings.issuers.empty()) throw std::invalid_argument("a relying party needs at least one issuer");
  if (settings.audience.empty()) throw std::invalid_argument("a relying party needs its audience");
  return settings;
}

std::string text_of(const dannan::identity::Secret& secret) {
  const auto bytes = secret.reveal();
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

}  // namespace

void discover(Https& https, const std::string& issuer, Deadline deadline, Executor executor, Done<Outcome<Endpoints>> done) {
  https.send(discovery_request(issuer), deadline, std::move(executor), [issuer, done = std::move(done)](Outcome<HttpsResponse> answered) {
    if (!answered.ok()) return done(Outcome<Endpoints>::failure(Fault::failed, issuer + "'s discovery: " + answered.message));
    auto document = json_answer(answered, issuer + "'s discovery");
    if (const auto* why = std::get_if<std::string>(&document)) return done(Outcome<Endpoints>::failure(Fault::refused, *why));
    auto endpoints = Endpoints::from_discovery(std::get<boost::json::object>(document), issuer);
    if (const auto* why = std::get_if<std::string>(&endpoints)) return done(Outcome<Endpoints>::failure(Fault::refused, issuer + "'s discovery: " + *why));
    done(Outcome<Endpoints>::success(std::get<Endpoints>(std::move(endpoints))));
  });
}

std::optional<std::string_view> bearer_token(std::string_view authorization) {
  constexpr std::string_view kScheme = "bearer";
  if (authorization.size() > kMostAuthorizationBytes || authorization.size() <= kScheme.size()) return std::nullopt;
  for (std::size_t i = 0; i < kScheme.size(); ++i) {
    const char c = authorization[i];
    if ((c >= 'A' && c <= 'Z' ? static_cast<char>(c - 'A' + 'a') : c) != kScheme[i]) return std::nullopt;
  }
  auto rest = authorization.substr(kScheme.size());
  if (rest.front() != ' ') return std::nullopt;
  rest.remove_prefix(std::min(rest.find_first_not_of(' '), rest.size()));
  // 1*( ALPHA / DIGIT / "-" / "." / "_" / "~" / "+" / "/" ) *"="
  std::size_t at = 0;
  while (at < rest.size() && b64token_char(rest[at])) ++at;
  if (at == 0) return std::nullopt;
  while (at < rest.size() && rest[at] == '=') ++at;
  if (at != rest.size()) return std::nullopt;
  return rest;
}

RelyingParty::RelyingParty(boost::asio::io_context& io, Settings settings, const dannan::contract::TimeSource& time, const dannan::contract::WallClock& wall)
    : _settings(checked(settings)),
      _owned(std::make_unique<HttpsClient>(io, _settings.ca_path)),
      _verifier(_settings.issuers, wall),
      _keys(HttpsKeySource::make(_verifier, *_owned, io.get_executor(), time, _settings.keys)) {}

RelyingParty::RelyingParty(Https& https, Executor executor, Settings settings, const dannan::contract::TimeSource& time,
                           const dannan::contract::WallClock& wall)
    : _settings(checked(settings)),
      _verifier(_settings.issuers, wall),
      _keys(HttpsKeySource::make(_verifier, https, std::move(executor), time, _settings.keys)) {}

RelyingParty::~RelyingParty() { _keys->stop(); }

void RelyingParty::start() { _keys->start(); }

void RelyingParty::stop() { _keys->stop(); }

std::variant<AccessToken, std::string> RelyingParty::verify(std::string_view token) const { return _verifier.verify_access(token, _settings.audience); }

std::variant<AccessToken, std::string> RelyingParty::verify_header(std::string_view authorization) const {
  const auto token = bearer_token(authorization);
  if (!token) return std::string("no bearer token in the Authorization header");
  return verify(*token);
}

std::shared_ptr<TokenSource> TokenSource::make(Https& https, Executor executor, Settings settings, const dannan::contract::TimeSource& time,
                                               const dannan::contract::WallClock& wall) {
  // Checked here, as the OAuth client would check them once discovery is read: by then a
  // refusal could only be thrown inside a handler.
  if (settings.issuers.empty()) throw std::invalid_argument("the token source needs at least one issuer");
  const auto& identity = settings.identity;
  if (identity.client_id.empty()) throw std::invalid_argument("the token source needs a client id");
  if (identity.method == Method::private_key_jwt) {
    if (!identity.key || identity.kid.empty()) throw std::invalid_argument("the token source's private_key_jwt needs a signing key and its kid");
  } else if (identity.method == Method::client_secret_basic) {
    if (!identity.secret) throw std::invalid_argument("the token source's client_secret_basic needs a secret");
  } else {
    throw std::invalid_argument("the token source needs a key (private_key_jwt) or a secret (client_secret_basic)");
  }
  return std::shared_ptr<TokenSource>(new TokenSource(https, std::move(executor), std::move(settings), time, wall));
}

TokenSource::TokenSource(Https& https, Executor executor, Settings settings, const dannan::contract::TimeSource& time, const dannan::contract::WallClock& wall)
    : _https(https),
      _settings(std::move(settings)),
      _time(time),
      _wall(wall),
      _verifier(_settings.issuers, wall),
      _strand(boost::asio::make_strand(std::move(executor))),
      _timer(_strand) {
  _clients.resize(_settings.issuers.size());
}

void TokenSource::start() {
  boost::asio::post(_strand, [self = shared_from_this()] {
    if (self->_running) return;
    self->_running = true;
    self->_fetch();
  });
}

void TokenSource::stop() {
  boost::asio::post(_strand, [self = shared_from_this()] {
    self->_running = false;
    self->_timer.cancel();
  });
}

std::optional<std::string> TokenSource::current() const {
  dannan::contract::Lock lock(_mutex);
  return _token;
}

TokenSource::Status TokenSource::status() const {
  dannan::contract::Lock lock(_mutex);
  return _status;
}

void TokenSource::_later(std::chrono::milliseconds delay) {
  if (!_running) return;
  _due = _time.now() + delay;
  _wait();
}

// A time source that does not follow the real clock wakes the timer early (wake_within), so each
// wake looks at the time again and sleeps on until the due time has come.
void TokenSource::_wait() {
  const auto remaining = std::max(std::chrono::ceil<std::chrono::milliseconds>(_due - _time.now()), std::chrono::milliseconds(0));
  if (remaining.count() == 0) return _fetch();
  _timer.expires_after(_time.wake_within(remaining));
  _timer.async_wait([weak = weak_from_this()](const boost::system::error_code& ec) {
    if (ec) return;
    if (const auto self = weak.lock(); self && self->_running) self->_wait();
  });
}

void TokenSource::_failed(std::string why) {
  {
    dannan::contract::Lock lock(_mutex);
    ++_status.failures;
    _status.last_error = std::move(why);
  }
  // The next issuer is asked next time, so one Lugh down costs one back-off, not a stall.
  _next = (_next + 1) % _settings.issuers.size();
  _later(_retries.failed(kRetry, _time.now()).value_or(kRetry.max_backoff));
}

void TokenSource::_fetch() {
  if (!_running) return;
  const auto index = _next;
  const auto& issuer = _settings.issuers[index];
  if (!_clients[index]) {
    discover(_https, issuer, _settings.step_deadline, _strand,
             [self = shared_from_this(), index](Outcome<Endpoints> found) { self->_discovered(index, std::move(found)); });
    return;
  }
  _clients[index]->client_credentials(_settings.scopes, _settings.step_deadline, _strand, [self = shared_from_this(), index](Outcome<TokenSet> got) {
    if (!self->_running) return;
    const auto& from = self->_settings.issuers[index];
    if (!got.ok() || !got.value.access_token) return self->_failed(from + ": " + (got.ok() ? "no access token in the answer" : got.message));
    {
      dannan::contract::Lock lock(self->_mutex);
      self->_token = text_of(*got.value.access_token);
      self->_status.issuer = from;
      self->_status.has_token = true;
      self->_status.failures = 0;
      self->_status.last_error.clear();
    }
    self->_retries.succeeded();
    const auto life = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::seconds(got.value.expires_in));
    self->_later(std::max<std::chrono::milliseconds>(kLeastRefresh, life * 2 / 3));
  });
}

void TokenSource::_discovered(std::size_t index, Outcome<Endpoints> found) {
  if (!_running) return;
  if (!found.ok()) return _failed(found.message);
  try {
    _clients[index] = std::make_unique<OAuthClient>(std::move(found.value), _settings.identity, _https, _verifier, _wall);
  } catch (const std::exception& refused) {
    return _failed(_settings.issuers[index] + ": " + refused.what());
  }
  _fetch();
}

}  // namespace lugh::client
