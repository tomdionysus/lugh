//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/scopes/topic_scope.h"

#include <stdexcept>

#include "dannan/encoding/percent.h"
#include "lugh/directory/records.h"
#include "lugh/scopes/scope.h"

namespace lugh::scopes {

namespace {

constexpr std::string_view kSubject = "{sub}";
// MQTT's limit on a topic filter, in bytes.
constexpr std::size_t kMostFilterBytes = 65535;

std::string_view action_text(TopicAction action) {
  switch (action) {
    case TopicAction::pub:
      return "pub";
    case TopicAction::sub:
      return "sub";
    case TopicAction::retain:
      return "retain";
  }
  return "sub";
}

std::optional<TopicAction> action_of(std::string_view text) {
  for (const auto action : {TopicAction::pub, TopicAction::sub, TopicAction::retain}) {
    if (action_text(action) == text) return action;
  }
  return std::nullopt;
}

const dannan::encoding::PercentSet& literal_set() {
  // Printable ASCII stays literal, '/', '+', '#' and '$' among it; space, controls and
  // non-ASCII are encoded by the set, '%' always, braces so that an unencoded brace is only
  // ever the subject's place, and '"' and '\', which no scope token may hold (RFC 6749
  // section 3.3): left literal, a level holding one encoded to a scope that is not a scope
  // (fuzz_scope, 2026-11-16).
  static const auto set = dannan::encoding::PercentSet::printable_ascii().encode("{}\"\\");
  return set;
}

}  // namespace

bool valid_filter(const std::vector<TopicLevel>& levels) {
  if (levels.empty()) return false;
  std::size_t bytes = levels.size() - 1;
  for (std::size_t i = 0; i < levels.size(); ++i) {
    const auto& level = levels[i];
    if (level.subject) {
      if (!level.text.empty()) return false;
      bytes += kSubject.size();
      continue;
    }
    bytes += level.text.size();
    if (level.text.find('/') != std::string::npos) return false;
    if (!directory::printable(level.text, kMostFilterBytes)) return false;
    const bool wildcard = level.text.find_first_of("+#") != std::string::npos;
    if (wildcard && level.text != "+" && level.text != "#") return false;
    if (level.text == "#" && i + 1 != levels.size()) return false;
  }
  // A filter of one empty level is the empty string, which MQTT refuses.
  if (levels.size() == 1 && !levels[0].subject && levels[0].text.empty()) return false;
  return bytes <= kMostFilterBytes;
}

std::optional<std::string> encode_topic(const TopicScope& scope) {
  if (!valid_filter(scope.levels)) return std::nullopt;
  std::string out = std::string(kTopicPrefix) + ":" + std::string(action_text(scope.action)) + ":";
  for (std::size_t i = 0; i < scope.levels.size(); ++i) {
    if (i > 0) out.push_back('/');
    const auto& level = scope.levels[i];
    out += level.subject ? std::string(kSubject) : dannan::encoding::percent_encode(level.text, literal_set());
  }
  if (out.size() > kMostScopeBytes) return std::nullopt;
  return out;
}

std::optional<TopicScope> decode_topic(std::string_view scope) {
  if (!well_formed(scope)) return std::nullopt;
  const auto first = scope.find(':');
  if (first == std::string_view::npos || scope.substr(0, first) != kTopicPrefix) return std::nullopt;
  const auto second = scope.find(':', first + 1);
  if (second == std::string_view::npos) return std::nullopt;
  const auto action = action_of(scope.substr(first + 1, second - first - 1));
  if (!action) return std::nullopt;

  TopicScope out;
  out.action = *action;
  const auto filter = scope.substr(second + 1);
  std::size_t at = 0;
  while (true) {
    const auto slash = filter.find('/', at);
    const auto raw = filter.substr(at, slash == std::string_view::npos ? std::string_view::npos : slash - at);
    TopicLevel level;
    if (raw == kSubject) {
      level.subject = true;
    } else {
      if (raw.find_first_of("{}") != std::string_view::npos) return std::nullopt;
      try {
        level.text = dannan::encoding::percent_decode(raw, dannan::encoding::Decoding::strict);
      } catch (const std::invalid_argument&) {
        return std::nullopt;
      }
    }
    out.levels.push_back(std::move(level));
    if (slash == std::string_view::npos) break;
    at = slash + 1;
  }
  if (!valid_filter(out.levels)) return std::nullopt;
  return out;
}

}  // namespace lugh::scopes
