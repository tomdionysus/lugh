//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "lugh/authn/password_hash.h"
#include "lugh/core/outcome.h"
#include "lugh/core/secure_bytes.h"
#include "lugh/store/store.h"

// An application: an OAuth client an administrator has registered and allowed
// (docs/architecture.md, "Applications"; TODO/2026-11-04-oauth.md, "Applications"). One record
// per application, keyed by its client_id, holding who may use it and how its groups map to
// its roles, so every change to it is one versioned write.
namespace lugh::apps {

enum class Kind : std::uint8_t {
  // A server-side backend: confidential.
  web = 1,
  // A browser or a native app: public, PKCE only.
  spa = 2,
  native = 3,
  // Machine to machine, no user: confidential.
  service = 4,
  // A resource server: it declares scopes under its prefix and is an audience.
  api = 5,
};

enum class ClientAuth : std::uint8_t { none = 1, private_key_jwt = 2, tls_client_auth = 3, client_secret_basic = 4 };

// The grants an application may use, as bits.
enum Grant : std::uint8_t {
  kAuthorizationCode = 0x01,
  kRefreshToken = 0x02,
  kDeviceCode = 0x04,
  kClientCredentials = 0x08,
};

enum class SenderConstraint : std::uint8_t { none = 1, dpop = 2, mtls = 3 };

// Removed is kept for ever, never written over: its client_id and prefix are never used
// again, so a new application can never take an old one's grants.
enum class State : std::uint8_t { enabled = 1, disabled = 2, removed = 3 };

struct RoleMapping {
  std::string group_id;
  std::vector<std::string> roles;

  bool operator==(const RoleMapping&) const = default;
};

// A client secret's Argon2id hash; `expires` is zero for the current one, and the moment
// (seconds since the epoch) a rotated one stops working.
struct ClientSecret {
  authn::PasswordHash hash;
  std::uint64_t expires = 0;
};

struct App {
  std::string client_id;
  std::uint64_t version = 0;

  std::string name;
  std::string icon_uri;
  std::string home_uri;
  Kind kind = Kind::web;
  // An api's scope prefix: its scopes are `<prefix>:<name>` and its audience is the prefix.
  // Empty for every other kind. Never changed.
  std::string prefix;

  ClientAuth auth = ClientAuth::none;
  // private_key_jwt: the JWK Set, as JSON text.
  std::string jwks;
  // tls_client_auth: the certificate's subject DN, or its SHA-256 thumbprint (base64url).
  std::string tls_subject;
  std::string tls_thumbprint;
  // client_secret_basic: the current secret, and a rotated one until it expires.
  std::vector<ClientSecret> secrets;

  std::vector<std::string> redirect_uris;
  std::vector<std::string> post_logout_uris;
  std::string backchannel_logout_uri;

  std::uint8_t grants = 0;
  // What the application may ask for on a user's behalf.
  std::vector<std::string> scopes;
  // The audiences its access tokens carry: "lugh", or a registered api's prefix.
  std::vector<std::string> audiences;
  // What it holds itself, calling with client credentials (the maintainer, 2026-11-04).
  std::vector<std::string> client_scopes;

  // The groups whose members may sign in to it.
  std::vector<std::string> access;
  // Groups mapped to its own role names, for its audience only.
  std::vector<RoleMapping> roles;

  // The least `acr` it needs, empty for the global and group policy alone; and how old a
  // sign-in may be, in seconds, zero for any.
  std::string acr;
  std::uint32_t max_age = 0;
  bool first_party = false;
  bool opaque_access_tokens = false;
  SenderConstraint sender = SenderConstraint::none;

  // Token lifetimes, in seconds.
  std::uint32_t access_seconds = 300;
  std::uint32_t id_seconds = 300;
  std::uint32_t refresh_idle_seconds = 86400;
  std::uint32_t refresh_absolute_seconds = 30 * 86400;

  State state = State::enabled;
  std::uint64_t created = 0;
  std::uint64_t updated = 0;
};

inline constexpr const char* kTable = "apps";
inline constexpr std::size_t kMostUris = 16;
inline constexpr std::size_t kMostUriBytes = 2048;
inline constexpr std::size_t kMostListed = 256;
inline constexpr std::size_t kMostRoles = 32;
inline constexpr std::size_t kMostJwksBytes = 16 * 1024;

// The grants each kind may have.
std::uint8_t grants_allowed(Kind kind);

// Whether `uri` may be a redirect URI for an application of `kind`: an absolute https URI
// without a fragment or user information, or, for a native app only, http on the loopback
// address (RFC 8252 section 7.3, whose port the app picks and the match ignores).
bool redirect_uri_ok(std::string_view uri, Kind kind);

// Whether `uri` is an absolute https URI without a fragment or user information.
bool https_uri_ok(std::string_view uri);

// A role name: letters, digits and . _ : -, 1 to 64.
bool role_name_ok(std::string_view role);

// Everything about the record that can be checked without the store: refused (invalid) with
// what was wanted. Whether its prefix is free, its audiences and scopes' prefixes registered,
// and its groups real, are the component's to check. `allow_client_secrets` is the policy
// that permits client_secret_basic.
Outcome<> validate(const App& app, bool allow_client_secrets);

SecureBuffer encode(const App& app);
std::optional<App> decode(std::span<const unsigned char> value);

// The apps table, indexed by prefix.
store::TableSpec table_spec();

}  // namespace lugh::apps
