//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <map>
#include <string>

#include "dannan/encoding/percent.h"
#include "lugh/authn/totp.h"
#include "lugh/core/encoding.h"
#include "lugh/test/fixtures/node_process.h"

// What a browser and an authenticator app do, for the process tests.
namespace node_process {

// A browser's cookies.
class Jar {
 public:
  void keep(const Reply& reply) {
    for (const auto& value : reply.all("Set-Cookie")) {
      const auto equals = value.find('=');
      const auto end = value.find(';');
      const auto name = value.substr(0, equals);
      if (value.find("Max-Age=0") != std::string::npos) {
        _cookies.erase(name);
      } else {
        _cookies[name] = value.substr(equals + 1, end - equals - 1);
      }
    }
  }
  std::string header() const {
    std::string out;
    for (const auto& [name, value] : _cookies) out += (out.empty() ? "" : "; ") + name + "=" + value;
    return out;
  }
  bool has(const std::string& name) const { return _cookies.count(name) > 0; }

 private:
  std::map<std::string, std::string> _cookies;
};

inline std::string between(const std::string& text, const std::string& before, const std::string& after) {
  const auto start = text.find(before);
  if (start == std::string::npos) return {};
  const auto from = start + before.size();
  return text.substr(from, text.find(after, from) - from);
}

inline std::string form(const std::map<std::string, std::string>& fields) {
  std::string out;
  for (const auto& [name, value] : fields) {
    out += (out.empty() ? "" : "&") + name + "=" + dannan::encoding::percent_encode(value, dannan::encoding::PercentSet::form());
  }
  return out;
}

// The code an authenticator app shows now for a base32 secret.
inline std::string code_now(const std::string& secret) {
  const auto raw = lugh::encoding::base32_decode(secret);
  const auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
  return lugh::authn::totp_code(*raw, lugh::authn::totp_step(static_cast<std::uint64_t>(now)));
}

}  // namespace node_process
