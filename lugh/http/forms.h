//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <map>
#include <optional>
#include <string>
#include <string_view>

#include "lugh/http/http_types.h"

// What a browser sends that is not JSON: a form body and cookies.
namespace lugh::http {

// The longest form Lugh reads: a sign-in form is a few fields.
inline constexpr std::size_t kMostFormBytes = 8 * 1024;

// An application/x-www-form-urlencoded body, its names and values decoded with Dannan's form
// decoding ('+' a space). Nothing for a body over the cap, a malformed escape, a field named
// twice, or a field with no name: a form that is not exactly one value per name is not
// guessed at.
std::optional<std::map<std::string, std::string>> parse_form(std::string_view body);

// The value of the cookie `name` in the request's Cookie headers (RFC 6265 section 5.4);
// nothing when it is absent, or present more than once, which only a forgery would make.
std::optional<std::string> cookie(const HttpRequest& request, std::string_view name);

// A Set-Cookie value for a __Host- cookie (RFC 6265bis): Secure, Path=/, no Domain, HttpOnly,
// SameSite=Lax, living `max_age` seconds; zero removes it.
std::string host_cookie(std::string_view name, std::string_view value, long max_age);

}  // namespace lugh::http
