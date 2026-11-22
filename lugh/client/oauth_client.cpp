//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/oauth_client.h"

#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <map>
#include <stdexcept>

#include "dannan/encoding/percent.h"
#include "dannan/identity/crypto.h"
#include "lugh/client/claims.h"
#include "lugh/client/dpop.h"
#include "lugh/client/jose.h"
#include "lugh/core/encoding.h"

namespace lugh::client {

namespace {

using Form = std::vector<std::pair<std::string, std::string>>;
using dannan::identity::Secret;

constexpr std::uint64_t kAssertionSeconds = 60;
constexpr const char* kAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

std::string random_text(std::size_t bytes) { return encoding::base64url(dannan::identity::random_bytes(bytes)); }

std::string encoded(std::string_view value) { return dannan::encoding::percent_encode(value, dannan::encoding::PercentSet::form()); }

std::string form_body(const Form& form) {
  std::string body;
  for (const auto& [name, value] : form) {
    if (!body.empty()) body += '&';
    body += encoded(name) + "=" + encoded(value);
  }
  return body;
}

std::string joined(const std::vector<std::string>& scopes) {
  std::string out;
  for (const auto& scope : scopes) out += (out.empty() ? "" : " ") + scope;
  return out;
}

// One value per name of an application/x-www-form-urlencoded string, or nothing for one that is
// not that.
std::optional<std::map<std::string, std::string>> parsed_query(std::string_view query) {
  std::map<std::string, std::string> out;
  try {
    while (!query.empty()) {
      const auto amp = query.find('&');
      const auto pair = query.substr(0, amp);
      const auto equals = pair.find('=');
      const auto name = dannan::encoding::percent_decode(pair.substr(0, equals), dannan::encoding::Decoding::form);
      const auto value =
          equals == std::string_view::npos ? std::string() : dannan::encoding::percent_decode(pair.substr(equals + 1), dannan::encoding::Decoding::form);
      if (!out.emplace(name, value).second) return std::nullopt;
      if (amp == std::string_view::npos) break;
      query.remove_prefix(amp + 1);
    }
  } catch (const std::invalid_argument&) {
    return std::nullopt;
  }
  return out;
}

bool https(const std::string& url) { return https_target(url).has_value(); }

}  // namespace

std::variant<Endpoints, std::string> Endpoints::from_discovery(const boost::json::object& discovery, std::string_view issuer) {
  const auto said = string_claim(discovery, "issuer");
  if (!said || *said != issuer) return std::string("the discovery document names another issuer");
  Endpoints out;
  out.issuer = *said;
  const auto take = [&](const char* name) { return string_claim(discovery, name).value_or(""); };
  out.authorization = take("authorization_endpoint");
  out.token = take("token_endpoint");
  out.pushed_authorization = take("pushed_authorization_request_endpoint");
  out.device_authorization = take("device_authorization_endpoint");
  out.userinfo = take("userinfo_endpoint");
  out.introspection = take("introspection_endpoint");
  out.revocation = take("revocation_endpoint");
  out.end_session = take("end_session_endpoint");
  if (const auto aliases = discovery.if_contains("mtls_endpoint_aliases"); aliases && aliases->is_object()) {
    const auto& named = aliases->as_object();
    const auto alias = [&](const char* name) {
      auto url = string_claim(named, name).value_or("");
      return https(url) ? url : std::string();
    };
    out.mtls.token = alias("token_endpoint");
    out.mtls.pushed_authorization = alias("pushed_authorization_request_endpoint");
    out.mtls.introspection = alias("introspection_endpoint");
    out.mtls.revocation = alias("revocation_endpoint");
    out.mtls.userinfo = alias("userinfo_endpoint");
  }
  if (!https(out.authorization) || !https(out.token)) return std::string("the discovery document has no https authorization or token endpoint");
  return out;
}

OAuthClient::OAuthClient(Endpoints endpoints, ClientIdentity identity, Https& https, const Verifier& verifier, const dannan::contract::WallClock& wall)
    : _endpoints(std::move(endpoints)), _identity(std::move(identity)), _https(https), _verifier(verifier), _wall(wall) {
  if (_identity.client_id.empty()) throw std::invalid_argument("a client needs a client_id");
  if (_identity.method == ClientIdentity::Method::private_key_jwt && (!_identity.key || _identity.kid.empty())) {
    throw std::invalid_argument("private_key_jwt needs a signing key and its kid");
  }
  if (_identity.method == ClientIdentity::Method::client_secret_basic && !_identity.secret) {
    throw std::invalid_argument("client_secret_basic needs a secret");
  }
}

AuthorizationRequest OAuthClient::authorization(const std::string& redirect_uri, const std::vector<std::string>& scopes) const {
  AuthorizationRequest request;
  request.redirect_uri = redirect_uri;
  request.state = random_text(16);
  request.nonce = random_text(16);
  // RFC 7636 section 4.1: 32 random bytes make a verifier of 43 unreserved characters.
  const auto verifier = random_text(32);
  request.code_verifier = std::make_shared<const Secret>(byte_span(verifier));
  const auto challenge = encoding::base64url(dannan::identity::sha256(request.code_verifier->reveal()).bytes);
  const Form parameters{{"response_type", "code"}, {"client_id", _identity.client_id}, {"redirect_uri", redirect_uri}, {"scope", joined(scopes)},
                        {"state", request.state},  {"nonce", request.nonce},           {"code_challenge", challenge},  {"code_challenge_method", "S256"}};
  request.url = _endpoints.authorization + "?" + form_body(parameters);
  return request;
}

void OAuthClient::pushed_authorization(const std::string& redirect_uri, const std::vector<std::string>& scopes, Deadline deadline, Executor executor,
                                       Done<Outcome<AuthorizationRequest>> done) {
  using Answer = Outcome<AuthorizationRequest>;
  auto request = authorization(redirect_uri, scopes);
  if (_endpoints.pushed_authorization.empty())
    return answer_now(executor, std::move(done), Answer::failure(Fault::invalid, "the issuer takes no pushed requests"));
  const auto query = request.url.substr(request.url.find('?') + 1);
  auto form = *parsed_query(query);
  // The client's authentication says who it is, once.
  form.erase("client_id");
  Form fields(form.begin(), form.end());
  HttpsRequest post;
  post.method = "POST";
  post.url = _identity.presents_certificate() && !_endpoints.mtls.pushed_authorization.empty() ? _endpoints.mtls.pushed_authorization
                                                                                               : _endpoints.pushed_authorization;
  post.content_type = "application/x-www-form-urlencoded";
  _authenticate(fields, post);
  post.body = form_body(fields);
  const auto client_id = _identity.client_id;
  const auto authorization_endpoint = _endpoints.authorization;
  _https.send(std::move(post), deadline, executor,
              [done = std::move(done), request = std::move(request), client_id, authorization_endpoint](Outcome<HttpsResponse> answered) mutable {
                if (!answered.ok()) return done(Answer::from(answered));
                boost::system::error_code ec;
                const auto body = boost::json::parse(answered.value.body, ec);
                if (ec || !body.is_object()) return done(Answer::failure(Fault::failed, "the pushed request's answer is not JSON"));
                if (answered.value.status != 201 && answered.value.status != 200) {
                  return done(Answer::failure(Fault::refused, string_claim(body.as_object(), "error").value_or("refused") + ": " +
                                                                  string_claim(body.as_object(), "error_description").value_or("")));
                }
                const auto uri = string_claim(body.as_object(), "request_uri");
                if (!uri) return done(Answer::failure(Fault::failed, "the pushed request's answer has no request_uri"));
                request.url = authorization_endpoint + "?" + form_body({{"client_id", client_id}, {"request_uri", *uri}});
                done(Answer::success(std::move(request)));
              });
}

Outcome<std::string> OAuthClient::callback(std::string_view query, const AuthorizationRequest& request) const {
  using Answer = Outcome<std::string>;
  const auto parameters = parsed_query(query);
  if (!parameters) return Answer::failure(Fault::invalid, "the return is not a query string");
  const auto value = [&](const char* name) -> std::optional<std::string> {
    const auto found = parameters->find(name);
    if (found == parameters->end()) return std::nullopt;
    return found->second;
  };
  // RFC 9207: the issuer says who it is, so a return from another issuer is not taken for its.
  if (value("iss") != _endpoints.issuer) return Answer::failure(Fault::refused, "the return is not from this issuer");
  if (value("state") != request.state) return Answer::failure(Fault::refused, "the return is for another request");
  if (const auto error = value("error")) return Answer::failure(Fault::refused, *error + ": " + value("error_description").value_or(""));
  const auto code = value("code");
  if (!code || code->empty()) return Answer::failure(Fault::invalid, "the return carries no code");
  return Answer::success(*code);
}

void OAuthClient::redeem(const std::string& code, const AuthorizationRequest& request, Deadline deadline, Executor executor, Done<Outcome<TokenSet>> done) {
  const auto& verifier = request.code_verifier->reveal();
  Form form{{"grant_type", "authorization_code"},
            {"code", code},
            {"redirect_uri", request.redirect_uri},
            {"code_verifier", std::string(verifier.begin(), verifier.end())}};
  _token(std::move(form), request.nonce, deadline, std::move(executor), std::move(done));
}

void OAuthClient::refresh(const Secret& refresh_token, const std::vector<std::string>& scopes, Deadline deadline, Executor executor,
                          Done<Outcome<TokenSet>> done) {
  const auto& token = refresh_token.reveal();
  Form form{{"grant_type", "refresh_token"}, {"refresh_token", std::string(token.begin(), token.end())}};
  if (!scopes.empty()) form.emplace_back("scope", joined(scopes));
  _token(std::move(form), std::nullopt, deadline, std::move(executor), std::move(done));
}

void OAuthClient::client_credentials(const std::vector<std::string>& scopes, Deadline deadline, Executor executor, Done<Outcome<TokenSet>> done) {
  Form form{{"grant_type", "client_credentials"}};
  if (!scopes.empty()) form.emplace_back("scope", joined(scopes));
  _token(std::move(form), std::nullopt, deadline, std::move(executor), std::move(done));
}

void OAuthClient::device_authorization(const std::vector<std::string>& scopes, Deadline deadline, Executor executor, Done<Outcome<DeviceAuthorization>> done) {
  using Answer = Outcome<DeviceAuthorization>;
  if (_endpoints.device_authorization.empty()) {
    return answer_now(executor, std::move(done), Answer::failure(Fault::invalid, "the issuer takes no device authorisations"));
  }
  Form form;
  if (!scopes.empty()) form.emplace_back("scope", joined(scopes));
  HttpsRequest post;
  post.method = "POST";
  post.url = _endpoints.device_authorization;
  post.content_type = "application/x-www-form-urlencoded";
  post.headers.emplace_back("Accept", "application/json");
  _authenticate(form, post);
  post.body = form_body(form);
  _https.send(std::move(post), deadline, executor, [done = std::move(done)](Outcome<HttpsResponse> answered) {
    if (!answered.ok()) return done(Answer::from(answered));
    boost::system::error_code ec;
    const auto parsed = boost::json::parse(answered.value.body, ec);
    if (ec || !parsed.is_object()) return done(Answer::failure(Fault::failed, "the device endpoint's answer is not JSON"));
    const auto& body = parsed.as_object();
    if (answered.value.status != 200) {
      return done(
          Answer::failure(Fault::refused, string_claim(body, "error").value_or("refused") + ": " + string_claim(body, "error_description").value_or("")));
    }
    const auto code = string_claim(body, "device_code");
    const auto user_code = string_claim(body, "user_code");
    const auto uri = string_claim(body, "verification_uri");
    const auto expires = seconds_claim(body, "expires_in");
    if (!code || code->empty() || !user_code || !uri || !expires) return done(Answer::failure(Fault::failed, "the device endpoint's answer is incomplete"));
    DeviceAuthorization started;
    started.device_code = std::make_shared<const Secret>(byte_span(*code));
    started.user_code = *user_code;
    started.verification_uri = *uri;
    started.verification_uri_complete = string_claim(body, "verification_uri_complete").value_or("");
    started.expires_in = static_cast<std::uint32_t>(*expires);
    // RFC 8628 section 3.2: five seconds when the issuer names no interval.
    started.interval = static_cast<std::uint32_t>(seconds_claim(body, "interval").value_or(5));
    if (started.interval == 0) started.interval = 5;
    done(Answer::success(std::move(started)));
  });
}

// One device authorisation's polls, on a strand of the caller's executor, waiting by the injected time.
class DevicePoll : public std::enable_shared_from_this<DevicePoll> {
 public:
  DevicePoll(OAuthClient& client, const DeviceAuthorization& started, const dannan::contract::TimeSource& time, Deadline deadline, Executor executor,
             Done<Outcome<TokenSet>> done)
      : _client(client),
        _code(started.device_code),
        _interval(std::chrono::seconds(started.interval)),
        _expires(time.now() + std::chrono::seconds(started.expires_in)),
        _time(time),
        _deadline(deadline),
        _strand(boost::asio::make_strand(std::move(executor))),
        _timer(_strand),
        _done(std::move(done)) {}

  void wait() {
    _due = _time.now() + _interval;
    _arm();
  }

 private:
  void _arm() {
    const auto now = _time.now();
    if (now >= _due) return _poll();
    const auto remaining = std::max(std::chrono::ceil<std::chrono::milliseconds>(_due - now), std::chrono::milliseconds(1));
    _timer.expires_after(_time.wake_within(remaining));
    _timer.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
      if (!ec) self->_arm();
    });
  }

  void _poll() {
    if (_time.now() >= _expires) return _done(Outcome<TokenSet>::failure(Fault::refused, "expired_token: the code expired before the person answered"));
    const auto& code = _code->reveal();
    Form form{{"grant_type", "urn:ietf:params:oauth:grant-type:device_code"}, {"device_code", std::string(code.begin(), code.end())}};
    _client._token(std::move(form), std::nullopt, _deadline, _strand, [self = shared_from_this()](Outcome<TokenSet> got) {
      if (got.fault == Fault::refused && got.message.rfind("authorization_pending:", 0) == 0) return self->wait();
      if (got.fault == Fault::refused && got.message.rfind("slow_down:", 0) == 0) {
        self->_interval += std::chrono::seconds(5);
        return self->wait();
      }
      self->_done(std::move(got));
    });
  }

  OAuthClient& _client;
  std::shared_ptr<const Secret> _code;
  std::chrono::seconds _interval;
  dannan::contract::TimePoint _expires;
  dannan::contract::TimePoint _due{};
  const dannan::contract::TimeSource& _time;
  Deadline _deadline;
  boost::asio::strand<Executor> _strand;
  boost::asio::steady_timer _timer;
  Done<Outcome<TokenSet>> _done;
};

void OAuthClient::device_tokens(const DeviceAuthorization& started, const dannan::contract::TimeSource& time, Deadline deadline, Executor executor,
                                Done<Outcome<TokenSet>> done) {
  std::make_shared<DevicePoll>(*this, started, time, deadline, std::move(executor), std::move(done))->wait();
}

void OAuthClient::_post(const std::string& url, const std::string& alias, Form form, Deadline deadline, Executor executor, Done<Outcome<HttpsResponse>> done) {
  HttpsRequest post;
  post.method = "POST";
  post.url = _identity.presents_certificate() && !alias.empty() ? alias : url;
  post.content_type = "application/x-www-form-urlencoded";
  post.headers.emplace_back("Accept", "application/json");
  _authenticate(form, post);
  post.body = form_body(form);
  _https.send(std::move(post), deadline, std::move(executor), std::move(done));
}

void OAuthClient::introspect(const Secret& token, Deadline deadline, Executor executor, Done<Outcome<Introspection>> done) {
  using Answer = Outcome<Introspection>;
  if (_endpoints.introspection.empty())
    return answer_now(executor, std::move(done), Answer::failure(Fault::invalid, "the issuer has no introspection endpoint"));
  const auto& bytes = token.reveal();
  _post(_endpoints.introspection, _endpoints.mtls.introspection, {{"token", std::string(bytes.begin(), bytes.end())}}, deadline, executor,
        [done = std::move(done)](Outcome<HttpsResponse> answered) {
          if (!answered.ok()) return done(Answer::from(answered));
          boost::system::error_code ec;
          const auto parsed = boost::json::parse(answered.value.body, ec);
          if (ec || !parsed.is_object()) return done(Answer::failure(Fault::failed, "the introspection answer is not JSON"));
          const auto& body = parsed.as_object();
          if (answered.value.status != 200) {
            return done(
                Answer::failure(Fault::refused, string_claim(body, "error").value_or("refused") + ": " + string_claim(body, "error_description").value_or("")));
          }
          const auto active = body.if_contains("active");
          if (!active || !active->is_bool()) return done(Answer::failure(Fault::failed, "the introspection answer says nothing of active"));
          Introspection out;
          out.claims = body;
          out.active = active->as_bool();
          out.token_type = string_claim(body, "token_type").value_or("");
          out.subject = string_claim(body, "sub").value_or("");
          out.client_id = string_claim(body, "client_id").value_or("");
          out.expires = seconds_claim(body, "exp").value_or(0);
          if (const auto scope = string_claim(body, "scope")) {
            std::string_view rest(*scope);
            while (!rest.empty()) {
              const auto space = rest.find(' ');
              if (const auto piece = rest.substr(0, space); !piece.empty()) out.scopes.emplace_back(piece);
              if (space == std::string_view::npos) break;
              rest.remove_prefix(space + 1);
            }
          }
          done(Answer::success(std::move(out)));
        });
}

void OAuthClient::revoke(const Secret& token, Deadline deadline, Executor executor, Done<Outcome<>> done) {
  using Answer = Outcome<>;
  if (_endpoints.revocation.empty()) return answer_now(executor, std::move(done), Answer::failure(Fault::invalid, "the issuer has no revocation endpoint"));
  const auto& bytes = token.reveal();
  _post(_endpoints.revocation, _endpoints.mtls.revocation, {{"token", std::string(bytes.begin(), bytes.end())}}, deadline, executor,
        [done = std::move(done)](Outcome<HttpsResponse> answered) {
          if (!answered.ok()) return done(Answer::from(answered));
          if (answered.value.status == 200) return done(Answer::success());
          boost::system::error_code ec;
          const auto parsed = boost::json::parse(answered.value.body, ec);
          if (ec || !parsed.is_object())
            return done(Answer::failure(answered.value.status == 503 ? Fault::unavailable : Fault::failed,
                                        "the revocation endpoint answered " + std::to_string(answered.value.status)));
          done(Answer::failure(Fault::refused, string_claim(parsed.as_object(), "error").value_or("refused") + ": " +
                                                   string_claim(parsed.as_object(), "error_description").value_or("")));
        });
}

std::optional<std::string> OAuthClient::dpop_proof_for(std::string_view method, std::string_view url, std::string_view access_token) const {
  if (!_identity.dpop_key) return std::nullopt;
  return dpop_proof(*_identity.dpop_key, method, url, _wall.unix_ms() / 1000, access_token);
}

void OAuthClient::_authenticate(Form& form, HttpsRequest& request) const {
  switch (_identity.method) {
    case ClientIdentity::Method::none:
    case ClientIdentity::Method::tls_client_auth:
      form.emplace_back("client_id", _identity.client_id);
      return;
    case ClientIdentity::Method::client_secret_basic: {
      // RFC 6749 section 2.3.1: each part form-encoded, then the pair in base64.
      const auto& secret = _identity.secret->reveal();
      const auto pair = encoded(_identity.client_id) + ":" + encoded(std::string_view(reinterpret_cast<const char*>(secret.data()), secret.size()));
      request.headers.emplace_back("Authorization", "Basic " + encoding::base64(byte_span(pair)));
      return;
    }
    case ClientIdentity::Method::private_key_jwt: {
      const auto now = _wall.unix_ms() / 1000;
      const boost::json::object claims{
          {"iss", _identity.client_id},    {"sub", _identity.client_id}, {"aud", _endpoints.token}, {"jti", random_text(16)}, {"iat", now},
          {"exp", now + kAssertionSeconds}};
      form.emplace_back("client_id", _identity.client_id);
      form.emplace_back("client_assertion_type", kAssertionType);
      form.emplace_back("client_assertion", jws_sign(*_identity.key, _identity.kid, "JWT", claims));
      return;
    }
  }
}

void OAuthClient::_token(Form form, std::optional<std::string> nonce, Deadline deadline, Executor executor, Done<Outcome<TokenSet>> done) {
  using Answer = Outcome<TokenSet>;
  HttpsRequest post;
  post.method = "POST";
  // RFC 8705 section 5: a client presenting its certificate calls the mTLS alias when there is one.
  post.url = _identity.presents_certificate() && !_endpoints.mtls.token.empty() ? _endpoints.mtls.token : _endpoints.token;
  post.content_type = "application/x-www-form-urlencoded";
  post.headers.emplace_back("Accept", "application/json");
  if (_identity.dpop_key) post.headers.emplace_back("DPoP", dpop_proof(*_identity.dpop_key, "POST", post.url, _wall.unix_ms() / 1000));
  _authenticate(form, post);
  post.body = form_body(form);
  _https.send(std::move(post), deadline, executor, [this, done = std::move(done), nonce = std::move(nonce)](Outcome<HttpsResponse> answered) {
    if (!answered.ok()) return done(Answer::from(answered));
    boost::system::error_code ec;
    const auto parsed = boost::json::parse(answered.value.body, ec);
    if (ec || !parsed.is_object()) return done(Answer::failure(Fault::failed, "the token endpoint's answer is not JSON"));
    const auto& body = parsed.as_object();
    if (answered.value.status != 200) {
      return done(
          Answer::failure(Fault::refused, string_claim(body, "error").value_or("refused") + ": " + string_claim(body, "error_description").value_or("")));
    }
    const auto access = string_claim(body, "access_token");
    const auto type = string_claim(body, "token_type");
    if (!access || access->empty() || !type) return done(Answer::failure(Fault::failed, "the token endpoint's answer has no access_token"));
    TokenSet tokens;
    tokens.access_token = std::make_shared<const Secret>(byte_span(*access));
    tokens.token_type = *type;
    tokens.expires_in = static_cast<std::uint32_t>(seconds_claim(body, "expires_in").value_or(0));
    if (const auto scope = string_claim(body, "scope")) {
      std::string_view rest(*scope);
      while (!rest.empty()) {
        const auto space = rest.find(' ');
        if (const auto piece = rest.substr(0, space); !piece.empty()) tokens.scopes.emplace_back(piece);
        if (space == std::string_view::npos) break;
        rest.remove_prefix(space + 1);
      }
    }
    if (const auto refresh = string_claim(body, "refresh_token")) tokens.refresh_token = std::make_shared<const Secret>(byte_span(*refresh));
    if (const auto id = string_claim(body, "id_token")) {
      auto checked = _verifier.verify_id(*id, _identity.client_id, nonce ? std::optional<std::string_view>(*nonce) : std::nullopt);
      if (const auto* why = std::get_if<std::string>(&checked)) return done(Answer::failure(Fault::refused, "the ID token: " + *why));
      tokens.id_token = std::get<IdToken>(std::move(checked));
      tokens.id_token_jwt = *id;
    }
    done(Answer::success(std::move(tokens)));
  });
}

}  // namespace lugh::client
