//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/post.hpp>
#include <boost/json.hpp>
#include <deque>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "dannan/encoding/percent.h"
#include "dannan/identity/secure_memory.h"
#include "lugh/client/https.h"
#include "lugh/client/testing.h"

// lugh_client's own fake, the one relying parties' tests use too.
using RecordingHttps = lugh::client::testing::FakeHttps;

// A form body or query string, one value per name.
inline std::map<std::string, std::string> fields_of(std::string_view text) {
  std::map<std::string, std::string> out;
  while (!text.empty()) {
    const auto amp = text.find('&');
    const auto pair = text.substr(0, amp);
    const auto equals = pair.find('=');
    out[dannan::encoding::percent_decode(pair.substr(0, equals), dannan::encoding::Decoding::form)] =
        dannan::encoding::percent_decode(pair.substr(equals + 1), dannan::encoding::Decoding::form);
    if (amp == std::string_view::npos) break;
    text.remove_prefix(amp + 1);
  }
  return out;
}

inline std::string text_of(const dannan::identity::Secret& secret) { return std::string(secret.reveal().begin(), secret.reveal().end()); }
