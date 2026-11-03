//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <map>
#include <string>

#include "http/caller.h"

// Bearer tokens the test names, each standing for a caller it names: what P6's sessions and
// OAuth tokens will resolve to, without them.
class FixedCallers : public lugh::http::CallerResolver {
 public:
  void add(const std::string& token, lugh::http::Caller caller) { _callers[token] = std::move(caller); }

  lugh::http::Caller resolve(const lugh::http::HttpRequest& request) const override {
    const auto header = request.find(lugh::http::field::authorization);
    if (header == request.end()) return {};
    const std::string value(header->value());
    if (value.rfind("Bearer ", 0) != 0) return {};
    const auto found = _callers.find(value.substr(7));
    return found == _callers.end() ? lugh::http::Caller{} : found->second;
  }

 private:
  std::map<std::string, lugh::http::Caller> _callers;
};
