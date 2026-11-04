//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Lir's topic scopes (the maintainer, 2026-11-04; TODO/2026-11-04-oauth.md, "Topic scopes, for Lir"):
//
//   topic-scope = "lir:" action ":" filter
//   action      = "pub" | "sub" | "retain"
//   filter      = an MQTT topic filter (MQTT 5.0 section 4.7), percent-encoded
//
// The filter's levels are split on '/', each then percent-decoded strictly with Dannan's
// decoder (dannan/encoding/percent.h). A level written exactly `{sub}` is replaced by the
// token's subject; any other unencoded brace is refused, so a literal brace is %7B or
// %7D. Lugh carries the grammar, refusing to grant a scope that does not decode to a valid
// filter; matching a topic against a filter is Lir's.
namespace lugh::scopes {

inline constexpr std::string_view kTopicPrefix = "lir";

enum class TopicAction { pub, sub, retain };

// One level of a filter: its text, decoded, or the subject's place.
struct TopicLevel {
  std::string text;
  bool subject = false;

  bool operator==(const TopicLevel&) const = default;
};

struct TopicScope {
  TopicAction action = TopicAction::sub;
  std::vector<TopicLevel> levels;

  bool operator==(const TopicScope&) const = default;
};

// Whether the levels make an MQTT topic filter: at least one level; each level's text
// printable UTF-8 (no U+0000, no other control character) with no '/'; '+' and '#' only as
// a whole level, '#' only as the last; a subject level has no text.
bool valid_filter(const std::vector<TopicLevel>& levels);

// The scope string, encoding every space, '%', brace, control character and non-ASCII byte;
// nothing for a filter that is not valid.
std::optional<std::string> encode_topic(const TopicScope& scope);

// The scope, decoded; nothing for anything that is not a valid topic scope.
std::optional<TopicScope> decode_topic(std::string_view scope);

}  // namespace lugh::scopes
