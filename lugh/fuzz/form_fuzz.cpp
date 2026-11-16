//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// What a browser posts to the sign-in pages before anyone is signed in: a form body and its
// Cookie headers. Input: the cookie header, a newline, then the body.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>

#include "lugh/http/forms.h"
#include "lugh/session/pre_sessions.h"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  using namespace lugh;
  const std::string input(reinterpret_cast<const char*>(data), size);
  const auto newline = input.find('\n');
  const auto cookies = input.substr(0, newline);
  const auto body = newline == std::string::npos ? std::string() : input.substr(newline + 1);

  if (const auto form = http::parse_form(body)) {
    for (const auto& [name, value] : *form) {
      if (name.empty()) std::abort();
    }
  }
  http::HttpRequest request{http::verb::post, "/signin", 11};
  try {
    request.set(http::field::cookie, cookies);
  } catch (const std::exception&) {
    return 0;
  }
  if (const auto handle = http::cookie(request, session::PreSessions::kCookie)) (void)session::PreSessions::handle_ok(*handle);
  return 0;
}
