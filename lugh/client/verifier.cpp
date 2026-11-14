//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/client/verifier.h"

#include <algorithm>
#include <stdexcept>

#include "lugh/client/access_token.h"
#include "lugh/client/claims.h"
#include "lugh/client/id_token.h"
#include "lugh/client/jose.h"

namespace lugh::client {

Verifier::Verifier(std::vector<std::string> issuers, const dannan::contract::WallClock& wall) : _issuers(std::move(issuers)), _wall(wall) {
  if (_issuers.empty()) throw std::invalid_argument("a verifier needs at least one issuer to trust");
  for (const auto& issuer : _issuers) {
    if (issuer.empty()) throw std::invalid_argument("an issuer to trust is empty");
  }
}

Verifier::~Verifier() = default;

std::size_t Verifier::set_keys(std::string_view issuer, const boost::json::object& jwks) {
  if (std::find(_issuers.begin(), _issuers.end(), issuer) == _issuers.end()) {
    throw std::invalid_argument("not an issuer this verifier trusts: " + std::string(issuer));
  }
  const auto list = jwks.if_contains("keys");
  if (!list || !list->is_array()) throw std::runtime_error("the JWKS of " + std::string(issuer) + " has no keys array");
  if (list->as_array().size() > kMostKeys) {
    throw std::runtime_error("the JWKS of " + std::string(issuer) + " holds more than " + std::to_string(kMostKeys) + " keys");
  }
  // What the document holds replaces what was held, even when that is nothing usable: a key
  // the issuer no longer publishes is no longer trusted.
  auto keys = std::make_shared<std::vector<VerifyKey>>();
  for (const auto& entry : list->as_array()) {
    if (!entry.is_object()) continue;
    auto key = from_jwk(entry.as_object());
    if (!key || key->kid.empty()) continue;
    keys->push_back(std::move(*key));
  }
  const auto taken = keys->size();
  dannan::contract::Lock lock(_mutex);
  _keys[std::string(issuer)] = std::move(keys);
  return taken;
}

std::variant<std::pair<std::string, Verifier::Keys>, std::string> Verifier::_keys_for(std::string_view token) const {
  const auto jws = jws_parse(token);
  if (!jws) return std::string("not a JWS Lugh reads");
  const auto iss = string_claim(jws->claims, "iss");
  if (!iss || std::find(_issuers.begin(), _issuers.end(), *iss) == _issuers.end()) return std::string("not from an issuer trusted");
  Keys keys;
  std::function<void(const std::string&)> hint;
  {
    dannan::contract::Lock lock(_mutex);
    if (const auto found = _keys.find(*iss); found != _keys.end()) keys = found->second;
    hint = _missing_keys;
  }
  const auto missing = [&](const char* why) -> std::string {
    if (hint) hint(*iss);
    return why;
  };
  if (!keys || keys->empty()) return missing("no keys yet for its issuer");
  const auto named = [&](const VerifyKey& key) { return key.kid == jws->kid; };
  if (std::none_of(keys->begin(), keys->end(), named)) return missing("no key with its kid");
  return std::pair<std::string, Keys>{*iss, std::move(keys)};
}

void Verifier::on_missing_keys(std::function<void(const std::string& issuer)> hint) {
  dannan::contract::Lock lock(_mutex);
  _missing_keys = std::move(hint);
}

std::variant<AccessToken, std::string> Verifier::verify_access(std::string_view token, std::optional<std::string_view> audience) const {
  auto found = _keys_for(token);
  if (const auto* why = std::get_if<std::string>(&found)) return *why;
  const auto& [issuer, keys] = std::get<0>(found);
  return check_access_token(token, *keys, issuer, _now(), audience);
}

std::variant<IdToken, std::string> Verifier::verify_id(std::string_view token, std::string_view client_id, std::optional<std::string_view> nonce) const {
  auto found = _keys_for(token);
  if (const auto* why = std::get_if<std::string>(&found)) return *why;
  const auto& [issuer, keys] = std::get<0>(found);
  return check_id_token(token, *keys, issuer, client_id, _now(), nonce);
}

}  // namespace lugh::client
