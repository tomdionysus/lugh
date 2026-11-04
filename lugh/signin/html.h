//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <memory>
#include <string>
#include <string_view>

#include "lugh/http/http_types.h"

// The sign-in pages' HTML: one layout, one stylesheet, and every value that is not Lugh's own
// text escaped on the way in.
namespace lugh::signin {

// `text` safe inside an element or a double-quoted attribute.
std::string escape(std::string_view text);

// A whole page around `body` (already HTML), titled `title` (text).
std::string page(std::string_view title, std::string_view body);

// The stylesheet the pages link to, in the dashboard's tokens (docs/architecture.md,
// "Frontend"): plain CSS, dark only.
std::string_view stylesheet();

// The policy every page is served under: nothing but the stylesheet, and forms posted only
// here (TODO/2026-11-04-oauth.md, "The pages").
inline constexpr const char* kPagePolicy =
    "default-src 'none'; style-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'";

// `html` as the response: text/html, never cached, under kPagePolicy.
void write_page(const std::shared_ptr<http::HttpResponse>& response, http::status status, const std::string& html);

// A 303 to `location`, on this server.
void write_redirect(const std::shared_ptr<http::HttpResponse>& response, std::string_view location);

}  // namespace lugh::signin
