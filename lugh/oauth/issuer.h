//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/json.hpp>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "dannan/contract/time_source.h"
#include "lugh/apps/app.h"
#include "lugh/authn/policy.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"
#include "lugh/directory/directory.h"
#include "lugh/http/caller.h"
#include "lugh/oauth/expiring.h"
#include "lugh/scopes/grants.h"
#include "lugh/tokens/signing_keys.h"

namespace lugh::oauth {

// A signed-in person's consent to an application, as an authorisation code carries it.
struct CodeGrant {
  std::string client_id;
  std::string redirect_uri;
  std::vector<std::string> scopes;
  std::string code_challenge;
  std::string nonce;
  std::string user_id;
  std::string sid;
  authn::Assurance acr = authn::Assurance::pwd;
  std::vector<std::string> amr;
  std::uint64_t auth_time = 0;
};

// What the token endpoint answers (RFC 6749 section 5.1).
struct Issued {
  std::string access_token;
  std::uint32_t expires_in = 0;
  std::vector<std::string> scopes;
  std::optional<std::string> id_token;
  std::optional<std::string> refresh_token;
  // "DPoP" for a token bound to the client's key, "Bearer" otherwise.
  std::string token_type = "Bearer";
};

// An access token, verified: its claims, and who it speaks for.
struct Bearer {
  boost::json::object claims;
  std::string subject;
  std::string client_id;
  // A client acting for itself (client credentials), not for a person.
  bool service = false;
  std::vector<std::string> scopes;
  // The thumbprint of the key the token is bound to (cnf.jkt, RFC 9449), if it is.
  std::optional<std::string> jkt;
  // The thumbprint of the certificate the token is bound to (cnf.x5t#S256, RFC 8705), if it is.
  std::optional<std::string> x5t;
};

// What an id_token_hint says (OIDC RP-Initiated Logout 1.0).
struct IdTokenHint {
  std::string client_id;
  std::string subject;
  std::string sid;
};

// Makes and checks Lugh's tokens (TODO/2026-11-04-oauth.md, "Tokens"). An access token is a
// JWT of RFC 9068 (`typ` at+jwt), signed ES256: iss, sub, aud, client_id, exp, iat, nbf, jti,
// scope, and for a person acr, amr, auth_time and sid. Its audiences are the application's,
// and its scopes are cut to what those audiences can use. An ID token (OIDC Core 2) is made
// when openid was granted: iss, sub, aud (the client), exp, iat, auth_time, nonce, acr, amr,
// azp, sid, at_hash, and the claims profile, email and groups allow, with the application's
// roles for the person's groups. Made with std::make_shared.
class TokenIssuer : public std::enable_shared_from_this<TokenIssuer> {
 public:
  TokenIssuer(std::shared_ptr<const tokens::SigningKeys> keys, std::string issuer, const dannan::contract::WallClock& wall,
              const dannan::contract::TimeSource& time, std::shared_ptr<directory::Directory> directory, std::shared_ptr<scopes::Grants> grants);

  const std::string& issuer() const { return _issuer; }

  // Tokens for the person in `grant`, through `app`; an ID token too when openid is granted
  // and `id_token` is asked for (a refresh asks for none). refused when the person can no
  // longer have them: removed, disabled, or not enrolled.
  // `cnf`, when given, binds the access token: to a DPoP key ({"jkt"}, RFC 9449) or a client
  // certificate ({"x5t#S256"}, RFC 8705).
  void for_person(apps::App app, CodeGrant grant, Deadline deadline, Executor executor, Done<Outcome<Issued>> done, bool id_token = true,
                  std::optional<boost::json::object> cnf = std::nullopt);

  // An access token stopped before it expires (RFC 7009): its jti refused until then. Held
  // in memory on this node.
  void revoke_access(const Bearer& bearer);

  // An access token for `app` acting as itself, with `asked` of its client scopes (all of them
  // when it asks for none). invalid for a scope it does not hold.
  Outcome<Issued> for_client(const apps::App& app, const std::vector<std::string>& asked, std::optional<boost::json::object> cnf = std::nullopt) const;

  // The claims userinfo answers for a person with `scopes` through `app`, as the ID token
  // carries them.
  void person_claims(std::string user_id, std::vector<std::string> scopes, std::optional<apps::App> app, Deadline deadline, Executor executor,
                     Done<Outcome<boost::json::object>> done);

  // An access token of Lugh's, checked: signed by a published key, at+jwt, this issuer's, in
  // its lifetime (a minute's skew allowed), and with `audience` among its audiences when one
  // is given. Never waits.
  std::optional<Bearer> verify(std::string_view token, std::optional<std::string_view> audience) const;

  // An ID token of Lugh's offered as a logout hint: signed by a published key and this issuer's.
  // Its lifetime is not checked: a person may sign out after their ID token has expired.
  std::optional<IdTokenHint> id_token_hint(std::string_view token) const;

  // A logout token for `client_id` (OIDC Back-Channel Logout 1.0, section 2.4), `typ`
  // logout+jwt, good for two minutes. Nothing when no key signs yet.
  std::optional<std::string> logout_token(const std::string& client_id, const std::string& user_id, const std::string& sid) const;

 private:
  std::uint64_t _now() const { return _wall.unix_ms() / 1000; }

  std::shared_ptr<const tokens::SigningKeys> _keys;
  std::string _issuer;
  const dannan::contract::WallClock& _wall;
  std::shared_ptr<directory::Directory> _directory;
  std::shared_ptr<scopes::Grants> _grants;
  // The jti of each access token revoked, kept as long as any access token lives.
  std::shared_ptr<Expiring<bool>> _revoked;
};

// The audiences an application's access tokens carry: its registered ones, or, for one that
// registered none, its own client_id, so the token is good at userinfo and nowhere else.
std::vector<std::string> audiences_of(const apps::App& app);

}  // namespace lugh::oauth
