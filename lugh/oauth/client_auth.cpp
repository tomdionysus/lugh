//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/oauth/client_auth.h"

#include <stdexcept>

#include "dannan/encoding/percent.h"
#include "dannan/identity/crypto.h"
#include "lugh/client/jose.h"
#include "lugh/core/encoding.h"
#include "lugh/core/steps.h"
#include "lugh/http/client_certificate.h"

namespace lugh::oauth {

namespace {

using Answer = Outcome<apps::App>;

constexpr Deadline kStepDeadline = std::chrono::seconds(30);
constexpr std::uint64_t kMostAssertionSeconds = 600;

Answer refused(std::string why) { return Answer::failure(Fault::refused, std::move(why)); }

std::string value_of(const Parameters& form, const std::string& name) {
  const auto found = form.find(name);
  return found == form.end() ? std::string() : found->second;
}

struct Basic {
  std::string client_id;
  std::string secret;
};

// The client_id and secret of an Authorization: Basic header, each form-decoded (RFC 6749
// section 2.3.1); nothing for a header that is not exactly that.
std::optional<Basic> basic_of(const http::HttpRequest& request) {
  const auto header = request.find(http::field::authorization);
  if (header == request.end()) return std::nullopt;
  const std::string value(header->value());
  if (value.rfind("Basic ", 0) != 0) return std::nullopt;
  const auto decoded = encoding::base64_decode(std::string_view(value).substr(6));
  if (!decoded) return Basic{};
  const std::string text(decoded->begin(), decoded->end());
  const auto colon = text.find(':');
  if (colon == std::string::npos) return Basic{};
  try {
    return Basic{dannan::encoding::percent_decode(text.substr(0, colon), dannan::encoding::Decoding::form),
                 dannan::encoding::percent_decode(text.substr(colon + 1), dannan::encoding::Decoding::form)};
  } catch (const std::invalid_argument&) {
    return Basic{};
  }
}

// Whether `aud` (a string or an array) names this server: its issuer or its token endpoint.
bool audience_ok(const boost::json::value* aud, const std::string& issuer) {
  if (!aud) return false;
  const auto ours = [&](const boost::json::value& one) {
    return one.is_string() && (one.as_string() == issuer || one.as_string() == issuer + "/oauth2/token" || one.as_string() == issuer + "/oauth2/par");
  };
  if (aud->is_array()) return std::any_of(aud->as_array().begin(), aud->as_array().end(), ours);
  return ours(*aud);
}

}  // namespace

ClientAuthenticator::ClientAuthenticator(std::shared_ptr<apps::Apps> apps, Executor hashing, const dannan::contract::WallClock& wall,
                                         const dannan::contract::TimeSource& time, std::string issuer)
    : _apps(std::move(apps)),
      _hashing(std::move(hashing)),
      _wall(wall),
      _issuer(std::move(issuer)),
      _seen(std::make_shared<Expiring<bool>>(time, std::chrono::seconds(kMostAssertionSeconds + 60), 100000)) {}

void ClientAuthenticator::authenticate(const http::HttpRequest& request, const Parameters& form, Deadline deadline, Executor executor,
                                       Done<Outcome<apps::App>> done) {
  auto answer = answering<apps::App>(deadline, executor, std::move(done), "the client was not authenticated within the deadline");
  const auto basic = basic_of(request);
  const auto assertion = value_of(form, "client_assertion");
  const auto form_client = value_of(form, "client_id");
  if (form.count("client_secret")) return answer->finish(refused("a client secret goes in the Authorization header, never the body"));
  if (basic && !assertion.empty()) return answer->finish(refused("one client authentication method, not two"));

  // Which client the request says it is.
  std::string client_id = form_client;
  std::optional<client::Jws> jws;
  if (basic) {
    if (basic->client_id.empty()) return answer->finish(refused("the Authorization header is not a client_id and secret"));
    client_id = basic->client_id;
  } else if (!assertion.empty()) {
    if (value_of(form, "client_assertion_type") != kAssertionType) return answer->finish(refused("client_assertion_type is " + std::string(kAssertionType)));
    jws = client::jws_parse(assertion);
    if (!jws) return answer->finish(refused("the client assertion is not a JWT Lugh can read"));
    const auto iss = jws->claims.if_contains("iss");
    if (!iss || !iss->is_string()) return answer->finish(refused("the client assertion has no iss"));
    client_id = std::string(iss->as_string());
  }
  if (client_id.empty()) return answer->finish(refused("no client_id"));
  if (!form_client.empty() && form_client != client_id) return answer->finish(refused("client_id is not the client that authenticated"));

  const auto self_seen = _seen;
  const auto hashing = _hashing;
  const auto issuer = _issuer;
  const auto now = _wall.unix_ms() / 1000;
  auto secret = std::make_shared<std::string>(basic ? basic->secret : std::string());
  _apps->app(client_id, kStepDeadline, executor, [=](Outcome<std::optional<apps::App>> found) {
    if (!found.ok()) return answer->finish(Answer::from(found));
    if (!found.value) return answer->finish(refused("no such client"));
    const auto app = *found.value;
    if (app.state != apps::State::enabled) return answer->finish(refused("this client is disabled"));

    switch (app.auth) {
      case apps::ClientAuth::none:
        if (basic || jws) return answer->finish(refused("this client is public: it presents no credential"));
        return answer->finish(Answer::success(app));

      case apps::ClientAuth::tls_client_auth: {
        // RFC 8705 section 2: the certificate presented on the mTLS listener, named by its
        // thumbprint (any certificate whose key the client holds), or by its subject (only one
        // that chains to the configured client CA, or anyone could make one with that name).
        if (basic || jws) return answer->finish(refused("this client authenticates with its certificate, and nothing else"));
        const auto certificate = http::client_certificate(request);
        if (!certificate) return answer->finish(refused("this client authenticates with a certificate, presented at the mTLS endpoint"));
        if (!app.tls_thumbprint.empty()) {
          if (!dannan::identity::constant_time_equal(byte_span(certificate->thumbprint), byte_span(app.tls_thumbprint)))
            return answer->finish(refused("the certificate is not this client's"));
          return answer->finish(Answer::success(app));
        }
        if (!certificate->verified || certificate->subject != app.tls_subject) return answer->finish(refused("the certificate is not this client's"));
        return answer->finish(Answer::success(app));
      }

      case apps::ClientAuth::private_key_jwt: {
        if (!jws) return answer->finish(refused("this client authenticates with private_key_jwt"));
        std::vector<client::VerifyKey> keys;
        boost::system::error_code ec;
        const auto set = boost::json::parse(app.jwks, ec);
        if (!ec && set.is_object()) {
          if (const auto list = set.as_object().if_contains("keys"); list && list->is_array()) {
            for (const auto& one : list->as_array()) {
              if (!one.is_object()) continue;
              if (auto key = client::from_jwk(one.as_object())) keys.push_back(std::move(*key));
            }
          }
        }
        if (!client::jws_verify(*jws, keys)) return answer->finish(refused("the client assertion is not signed by a key this client registered"));
        const auto& claims = jws->claims;
        const auto sub = claims.if_contains("sub");
        const auto exp = claims.if_contains("exp");
        const auto jti = claims.if_contains("jti");
        if (!sub || !sub->is_string() || sub->as_string() != client_id) return answer->finish(refused("the client assertion's sub is not its client_id"));
        if (!audience_ok(claims.if_contains("aud"), issuer)) return answer->finish(refused("the client assertion is not for this server"));
        if (!exp || !exp->is_number()) return answer->finish(refused("the client assertion has no exp"));
        const auto expires = exp->to_number<double>();
        if (expires <= static_cast<double>(now) || expires > static_cast<double>(now + kMostAssertionSeconds))
          return answer->finish(refused("the client assertion has expired, or lives longer than ten minutes"));
        if (!jti || !jti->is_string() || jti->as_string().empty()) return answer->finish(refused("the client assertion has no jti"));
        if (!self_seen->put_as(client_id + " " + std::string(jti->as_string()), true)) return answer->finish(refused("the client assertion was used before"));
        return answer->finish(Answer::success(app));
      }

      case apps::ClientAuth::client_secret_basic: {
        if (!basic) return answer->finish(refused("this client authenticates with client_secret_basic"));
        auto hashes = std::make_shared<std::vector<authn::PasswordHash>>();
        for (const auto& one : app.secrets) {
          if (one.expires == 0 || one.expires > now) hashes->push_back(one.hash);
        }
        return on_pool(
            hashing,
            [secret, hashes] {
              bool right = false;
              for (const auto& hash : *hashes) right = authn::verify_password(byte_span(*secret), hash) || right;
              return right;
            },
            executor, [answer, app](bool right) { answer->finish(right ? Answer::success(app) : refused("the client secret is not right")); });
      }
    }
    answer->finish(refused("this client cannot authenticate"));
  });
}

}  // namespace lugh::oauth
