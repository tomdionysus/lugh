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
std::string page(std::string_view title, std::string_view body, std::string_view head = {});

// The stylesheet the pages link to, in the dashboard's tokens (docs/architecture.md,
// "Frontend"): plain CSS, dark only.
std::string_view stylesheet();

// The policy every page is served under: the stylesheet, one first-party script for WebAuthn and
// what it fetches from here, and forms posted only here (TODO/2026-11-04-oauth.md, "The pages";
// P11). No inline script and no other origin.
inline constexpr const char* kPagePolicy =
    "default-src 'none'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; "
    "base-uri 'none'";

// The script the pages load for WebAuthn.
std::string_view webauthn_script();

// `html` as the response: text/html, never cached, under kPagePolicy.
void write_page(const std::shared_ptr<http::HttpResponse>& response, http::status status, const std::string& html);

// A 303 to `location`.
void write_redirect(const std::shared_ptr<http::HttpResponse>& response, std::string_view location);

// On to `location` on another server, from a form's answer: a page that goes there by itself,
// and a link if it does not. A 303 would not do: form-action 'self' covers where a form's answer
// redirects to, and browsers that enforce that stop it there.
void write_leaving(const std::shared_ptr<http::HttpResponse>& response, std::string_view location);

}  // namespace lugh::signin
