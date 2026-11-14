//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/oauth_client.h"

#include <map>
#include <stdexcept>

#include "dannan/encoding/percent.h"
#include "dannan/identity/crypto.h"
#include "lugh/client/claims.h"
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
  post.url = _endpoints.pushed_authorization;
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

void OAuthClient::_authenticate(Form& form, HttpsRequest& request) const {
  switch (_identity.method) {
    case ClientIdentity::Method::none:
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
  post.url = _endpoints.token;
  post.content_type = "application/x-www-form-urlencoded";
  post.headers.emplace_back("Accept", "application/json");
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
