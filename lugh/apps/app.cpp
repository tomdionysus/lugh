//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/apps/app.h"

#include <algorithm>
#include <boost/json.hpp>
#include <set>

#include "lugh/authn/policy.h"
#include "lugh/core/codec.h"
#include "lugh/directory/records.h"
#include "lugh/scopes/scope.h"

namespace lugh::apps {

namespace {

constexpr std::uint8_t kFormat = 1;
constexpr std::uint32_t kYear = 365 * 86400;

using Answer = Outcome<>;

Answer refused(std::string why) { return Answer::failure(Fault::invalid, std::move(why)); }

// Printable ASCII, no space: what a URI may hold before any of it is looked at.
bool plain_ascii(std::string_view text) {
  return std::all_of(text.begin(), text.end(), [](char c) { return c > 0x20 && c < 0x7f; });
}

// The authority of an absolute `scheme://authority...` URI, or nothing.
std::optional<std::string_view> authority_of(std::string_view uri, std::string_view scheme) {
  const auto start = std::string(scheme) + "://";
  if (uri.size() > kMostUriBytes || !plain_ascii(uri) || uri.rfind(start, 0) != 0) return std::nullopt;
  if (uri.find('#') != std::string_view::npos) return std::nullopt;
  const auto rest = uri.substr(start.size());
  const auto authority = rest.substr(0, rest.find_first_of("/?"));
  if (authority.empty() || authority.find('@') != std::string_view::npos) return std::nullopt;
  return authority;
}

// The host of an authority, without its port, when the port is digits or absent.
std::optional<std::string_view> host_of(std::string_view authority) {
  std::string_view host = authority;
  std::string_view port;
  if (authority.front() == '[') {
    const auto close = authority.find(']');
    if (close == std::string_view::npos) return std::nullopt;
    host = authority.substr(0, close + 1);
    const auto after = authority.substr(close + 1);
    if (!after.empty()) {
      if (after.front() != ':') return std::nullopt;
      port = after.substr(1);
    }
  } else if (const auto colon = authority.find(':'); colon != std::string_view::npos) {
    host = authority.substr(0, colon);
    port = authority.substr(colon + 1);
  }
  if (host.empty()) return std::nullopt;
  if (!std::all_of(port.begin(), port.end(), [](char c) { return c >= '0' && c <= '9'; }) || port.size() > 5) return std::nullopt;
  return host;
}

Answer uris(const std::vector<std::string>& list, Kind kind, const char* what) {
  if (list.size() > kMostUris) return refused(std::string(what) + ": at most 16");
  std::set<std::string> seen;
  for (const auto& uri : list) {
    if (!redirect_uri_ok(uri, kind))
      return refused(std::string(what) + ": " + uri + " is not an https URI without a fragment" +
                     (kind == Kind::native ? ", or http on 127.0.0.1 or [::1]" : ""));
    if (!seen.insert(uri).second) return refused(std::string(what) + ": " + uri + " is listed twice");
  }
  return Answer::success();
}

Answer scope_list(const std::vector<std::string>& list, const char* what) {
  if (list.size() > kMostListed) return refused(std::string(what) + ": at most 256");
  for (const auto& scope : list) {
    const auto kind = scopes::grantable(scope);
    if (!kind.ok()) return refused(std::string(what) + ": " + kind.message);
  }
  return Answer::success();
}

// A JWK Set of public keys, as private_key_jwt needs: an object whose `keys` is a non-empty
// array of objects, each with a kty Lugh can verify with (EC or OKP), and none holding a
// private part. The keys themselves are parsed with the tokens (O4).
Answer jwks_ok(const std::string& text) {
  if (text.empty() || text.size() > kMostJwksBytes) return refused("jwks is a JWK Set, at most 16 KiB");
  boost::system::error_code ec;
  const auto parsed = boost::json::parse(text, ec);
  if (ec || !parsed.is_object()) return refused("jwks is a JWK Set: a JSON object");
  const auto keys = parsed.as_object().if_contains("keys");
  if (!keys || !keys->is_array() || keys->as_array().empty()) return refused("jwks needs at least one key in keys");
  for (const auto& key : keys->as_array()) {
    if (!key.is_object()) return refused("each key in jwks is an object");
    const auto& object = key.as_object();
    const auto kty = object.if_contains("kty");
    if (!kty || !kty->is_string() || (kty->as_string() != "EC" && kty->as_string() != "OKP")) return refused("each key in jwks has kty EC or OKP");
    if (object.contains("d")) return refused("jwks holds a private key: give Lugh the public keys only");
  }
  return Answer::success();
}

void write_strings(SecureWriter& writer, const std::vector<std::string>& list) {
  writer.u32(static_cast<std::uint32_t>(list.size()));
  for (const auto& item : list) writer.string(item);
}

std::vector<std::string> read_strings(dannan::net::Reader& reader) {
  const auto count = reader.u32();
  if (count > kMostListed) throw dannan::net::DecodeError("too many");
  std::vector<std::string> out;
  out.reserve(count);
  for (std::uint32_t i = 0; i < count; ++i) out.push_back(reader.string(kMostFieldBytes));
  return out;
}

template <typename E>
std::optional<E> enum_of(std::uint8_t value, std::uint8_t least, std::uint8_t most) {
  if (value < least || value > most) return std::nullopt;
  return static_cast<E>(value);
}

}  // namespace

std::uint8_t grants_allowed(Kind kind) {
  switch (kind) {
    case Kind::web:
      return kAuthorizationCode | kRefreshToken | kClientCredentials;
    case Kind::spa:
      return kAuthorizationCode | kRefreshToken;
    case Kind::native:
      return kAuthorizationCode | kRefreshToken | kDeviceCode;
    case Kind::service:
    case Kind::api:
      return kClientCredentials;
  }
  return 0;
}

bool https_uri_ok(std::string_view uri) {
  const auto authority = authority_of(uri, "https");
  return authority && host_of(*authority);
}

bool redirect_uri_ok(std::string_view uri, Kind kind) {
  if (https_uri_ok(uri)) return true;
  if (kind != Kind::native) return false;
  const auto authority = authority_of(uri, "http");
  if (!authority) return false;
  const auto host = host_of(*authority);
  return host && (*host == "127.0.0.1" || *host == "[::1]");
}

bool role_name_ok(std::string_view role) {
  if (role.empty() || role.size() > 64) return false;
  return std::all_of(role.begin(), role.end(), [](char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == ':' || c == '-';
  });
}

Outcome<> validate(const App& app, bool allow_client_secrets) {
  if (app.name.empty() || !directory::printable(app.name, 128)) return refused("name is printable UTF-8, 1 to 128 bytes");
  if (!app.icon_uri.empty() && !https_uri_ok(app.icon_uri)) return refused("icon_uri is an https URI");
  if (!app.home_uri.empty() && !https_uri_ok(app.home_uri)) return refused("home_uri is an https URI");

  // Who the client is.
  const bool is_public = app.kind == Kind::spa || app.kind == Kind::native;
  if (is_public && app.auth != ClientAuth::none) return refused("a spa or native app is public: client_authentication is none, and it uses PKCE");
  if ((app.kind == Kind::web || app.kind == Kind::service) && app.auth == ClientAuth::none)
    return refused("a web or service app authenticates: private_key_jwt, tls_client_auth, or client_secret_basic where policy allows");
  if (app.auth == ClientAuth::client_secret_basic && !allow_client_secrets) return refused("client_secret_basic is not allowed by policy");
  if (app.auth == ClientAuth::private_key_jwt) {
    if (const auto keys = jwks_ok(app.jwks); !keys.ok()) return keys;
  } else if (!app.jwks.empty()) {
    return refused("jwks is for private_key_jwt");
  }
  if (app.auth == ClientAuth::tls_client_auth) {
    if (app.tls_subject.empty() == app.tls_thumbprint.empty())
      return refused("tls_client_auth names the certificate by its subject DN or its thumbprint, one of them");
    if (!app.tls_subject.empty() && !directory::printable(app.tls_subject, 512)) return refused("the subject DN is printable, at most 512 bytes");
    if (!app.tls_thumbprint.empty() && (app.tls_thumbprint.size() != 43 || !std::all_of(app.tls_thumbprint.begin(), app.tls_thumbprint.end(), [](char c) {
                                          return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
                                        })))
      return refused("the thumbprint is a SHA-256 in base64url, 43 characters");
  } else if (!app.tls_subject.empty() || !app.tls_thumbprint.empty()) {
    return refused("a certificate is named for tls_client_auth only");
  }

  // What it is.
  if (app.kind == Kind::api) {
    if (!scopes::valid_prefix(app.prefix)) return refused("an api's scope_prefix is a lower-case letter, then lower-case letters, digits and '-', at most 32");
    if (app.prefix == scopes::kLughPrefix) return refused("the scope prefix lugh is Lugh's own");
  } else if (!app.prefix.empty()) {
    return refused("only an api has a scope_prefix");
  }

  // What it may do.
  if ((app.grants & ~grants_allowed(app.kind)) != 0) return refused("a grant this kind of app may not use");
  if (app.grants == 0 && app.kind != Kind::api) return refused("grant_types names at least one grant");
  if ((app.grants & kRefreshToken) && !(app.grants & (kAuthorizationCode | kDeviceCode)))
    return refused("refresh_token comes with authorization_code or the device grant");
  const bool signs_users_in = (app.grants & kAuthorizationCode) != 0;
  if (signs_users_in && app.redirect_uris.empty()) return refused("authorization_code needs at least one redirect URI");
  if (!signs_users_in && (!app.redirect_uris.empty() || !app.post_logout_uris.empty() || !app.backchannel_logout_uri.empty()))
    return refused("redirect and logout URIs are for an app with authorization_code");
  if (const auto ok = uris(app.redirect_uris, app.kind, "redirect_uris"); !ok.ok()) return ok;
  if (const auto ok = uris(app.post_logout_uris, app.kind, "post_logout_redirect_uris"); !ok.ok()) return ok;
  if (!app.backchannel_logout_uri.empty() && !https_uri_ok(app.backchannel_logout_uri)) return refused("backchannel_logout_uri is an https URI");

  if (const auto ok = scope_list(app.scopes, "scopes"); !ok.ok()) return ok;
  if (const auto ok = scope_list(app.client_scopes, "client_scopes"); !ok.ok()) return ok;
  if (!app.client_scopes.empty() && !(app.grants & kClientCredentials)) return refused("client_scopes are for an app with client_credentials");
  if (app.audiences.size() > kMostRoles) return refused("audiences: at most 32");
  for (const auto& audience : app.audiences) {
    if (audience != scopes::kLughPrefix && !scopes::valid_prefix(audience)) return refused("an audience is lugh or an api's scope prefix, not " + audience);
  }

  // Who may use it.
  if (app.access.size() > kMostListed) return refused("access: at most 256 groups");
  if (app.roles.size() > kMostListed) return refused("roles: at most 256 groups");
  for (const auto& mapping : app.roles) {
    if (mapping.roles.empty() || mapping.roles.size() > kMostRoles) return refused("a group maps to 1 to 32 roles");
    for (const auto& role : mapping.roles) {
      if (!role_name_ok(role)) return refused("a role is letters, digits and . _ : -, 1 to 64, not " + role);
    }
  }

  // How sure, and how long.
  if (!app.acr.empty() && !authn::assurance_from_acr(app.acr)) return refused("acr is urn:lugh:acr:pwd, urn:lugh:acr:mfa or urn:lugh:acr:phr");
  if (app.max_age > kYear) return refused("max_age is at most a year");
  if (app.access_seconds < 60 || app.access_seconds > 3600) return refused("an access token lives 60 to 3600 seconds");
  if (app.id_seconds < 60 || app.id_seconds > 3600) return refused("an ID token lives 60 to 3600 seconds");
  if (app.refresh_idle_seconds < 300 || app.refresh_idle_seconds > app.refresh_absolute_seconds || app.refresh_absolute_seconds > kYear)
    return refused("a refresh token's idle lifetime is at least 300 seconds and within its absolute one, at most a year");
  return Answer::success();
}

SecureBuffer encode(const App& app) {
  SecureWriter writer;
  writer.u8(kFormat);
  writer.string(app.name);
  writer.string(app.icon_uri);
  writer.string(app.home_uri);
  writer.u8(static_cast<std::uint8_t>(app.kind));
  writer.string(app.prefix);
  writer.u8(static_cast<std::uint8_t>(app.auth));
  writer.string(app.jwks);
  writer.string(app.tls_subject);
  writer.string(app.tls_thumbprint);
  writer.u32(static_cast<std::uint32_t>(app.secrets.size()));
  for (const auto& secret : app.secrets) {
    authn::write_password_hash(writer, secret.hash);
    writer.u64(secret.expires);
  }
  write_strings(writer, app.redirect_uris);
  write_strings(writer, app.post_logout_uris);
  writer.string(app.backchannel_logout_uri);
  writer.u8(app.grants);
  write_strings(writer, app.scopes);
  write_strings(writer, app.audiences);
  write_strings(writer, app.client_scopes);
  write_strings(writer, app.access);
  writer.u32(static_cast<std::uint32_t>(app.roles.size()));
  for (const auto& mapping : app.roles) {
    writer.string(mapping.group_id);
    write_strings(writer, mapping.roles);
  }
  writer.string(app.acr);
  writer.u32(app.max_age);
  writer.u8(static_cast<std::uint8_t>((app.first_party ? 1 : 0) | (app.opaque_access_tokens ? 2 : 0)));
  writer.u8(static_cast<std::uint8_t>(app.sender));
  writer.u32(app.access_seconds);
  writer.u32(app.id_seconds);
  writer.u32(app.refresh_idle_seconds);
  writer.u32(app.refresh_absolute_seconds);
  writer.u8(static_cast<std::uint8_t>(app.state));
  writer.u64(app.created);
  writer.u64(app.updated);
  return writer.take();
}

std::optional<App> decode(std::span<const unsigned char> value) {
  return decode_whole<App>(value, [](dannan::net::Reader& reader) -> std::optional<App> {
    if (reader.u8() != kFormat) return std::nullopt;
    App app;
    app.name = reader.string(kMostFieldBytes);
    app.icon_uri = reader.string(kMostFieldBytes);
    app.home_uri = reader.string(kMostFieldBytes);
    const auto kind = enum_of<Kind>(reader.u8(), 1, 5);
    app.prefix = reader.string(kMostFieldBytes);
    const auto auth = enum_of<ClientAuth>(reader.u8(), 1, 4);
    if (!kind || !auth) return std::nullopt;
    app.kind = *kind;
    app.auth = *auth;
    app.jwks = reader.string(kMostJwksBytes);
    app.tls_subject = reader.string(kMostFieldBytes);
    app.tls_thumbprint = reader.string(kMostFieldBytes);
    const auto secrets = reader.u32();
    if (secrets > 2) return std::nullopt;
    for (std::uint32_t i = 0; i < secrets; ++i) {
      auto hash = authn::read_password_hash(reader);
      if (!hash) return std::nullopt;
      app.secrets.push_back(ClientSecret{std::move(*hash), reader.u64()});
    }
    app.redirect_uris = read_strings(reader);
    app.post_logout_uris = read_strings(reader);
    app.backchannel_logout_uri = reader.string(kMostFieldBytes);
    app.grants = reader.u8();
    app.scopes = read_strings(reader);
    app.audiences = read_strings(reader);
    app.client_scopes = read_strings(reader);
    app.access = read_strings(reader);
    const auto roles = reader.u32();
    if (roles > kMostListed) return std::nullopt;
    for (std::uint32_t i = 0; i < roles; ++i) {
      RoleMapping mapping;
      mapping.group_id = reader.string(kMostFieldBytes);
      mapping.roles = read_strings(reader);
      app.roles.push_back(std::move(mapping));
    }
    app.acr = reader.string(kMostFieldBytes);
    app.max_age = reader.u32();
    const auto flags = reader.u8();
    if ((flags & ~3) != 0) return std::nullopt;
    app.first_party = (flags & 1) != 0;
    app.opaque_access_tokens = (flags & 2) != 0;
    const auto sender = enum_of<SenderConstraint>(reader.u8(), 1, 3);
    if (!sender) return std::nullopt;
    app.sender = *sender;
    app.access_seconds = reader.u32();
    app.id_seconds = reader.u32();
    app.refresh_idle_seconds = reader.u32();
    app.refresh_absolute_seconds = reader.u32();
    const auto state = enum_of<State>(reader.u8(), 1, 3);
    if (!state) return std::nullopt;
    app.state = *state;
    app.created = reader.u64();
    app.updated = reader.u64();
    return app;
  });
}

store::TableSpec table_spec() {
  // A removed app keeps its prefix in the index, so the prefix is never taken again.
  store::IndexSpec prefix{"prefix", [](std::span<const unsigned char> value) {
                            const auto app = decode(value);
                            return app && !app->prefix.empty() ? std::vector<std::string>{app->prefix} : std::vector<std::string>{};
                          }};
  return store::TableSpec{kTable, {prefix}};
}

}  // namespace lugh::apps
