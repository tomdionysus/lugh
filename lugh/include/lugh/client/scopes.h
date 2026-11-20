//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Scopes as a relying party reads them, and Lir's topic scopes (the maintainer, 2026-11-04;
// TODO/2026-11-04-oauth.md, "Topic scopes, for Lir"). One grammar for the stack: lugh-node
// grants by it and Lir checks by it (the stack's placement plan, L3).
//
//   topic-scope = "lir:" action ":" filter
//   action      = "pub" | "sub" | "retain"
//   filter      = an MQTT topic filter (MQTT 5.0 section 4.7), percent-encoded
//
// The filter's levels are split on '/', each then percent-decoded strictly with Dannan's
// decoder, so an encoded '/' never makes a level boundary. A level written exactly `{sub}`
// is the token's subject; any other unencoded brace is refused, so a literal brace is %7B or
// %7D. `pub` is a PUBLISH without the retain flag to a topic the filter matches; `retain` is
// one with it, and does not imply `pub`; `sub` is a SUBSCRIBE whose filter the granted one
// covers, the filter inside `$share/<group>/` for a shared one.
//
// Everything here is pure and answers from memory: no network, issuer or key source, so a
// broker parses its own configuration's scopes for anonymous clients the same way.
namespace lugh::client {

// The longest scope Lugh grants. A topic filter is the long one; a token over its own cap is
// refused when issued, which is what keeps tokens small.
inline constexpr std::size_t kMostScopeBytes = 1024;

// One word of RFC 6749 section 3.3: printable ASCII, no space, '"' or '\\', not empty, at most
// kMostScopeBytes.
bool well_formed(std::string_view scope);

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

// A "lir:" scope left out of a grant, and why.
struct RefusedScope {
  std::string scope;
  std::string why;

  bool operator==(const RefusedScope&) const = default;
};

// What a set of scopes lets a client publish, retain and subscribe to, the subject put in
// place of each `{sub}`. Immutable once parsed, so any thread may ask it.
class TopicGrants {
 public:
  // From a token's scope claim, or a broker's configured scopes for anonymous clients;
  // `subject` empty for none. Other applications' scopes are skipped silently. A "lir:"
  // scope is refused, with why, when it does not decode, names `{sub}` with no subject or a
  // subject that is not one literal topic level, or grants a shared-subscription filter.
  static TopicGrants parse(std::span<const std::string> scopes, std::string_view subject = {});

  // The checks against a PUBLISH or a SUBSCRIBE come with lir::mqtt, which owns MQTT's topic
  // rules (validity, matching, coverage, shared filters; the stack's placement plan).

  // The granted filters, decoded and with the subject in place, in the order given.
  const std::vector<std::string>& publish() const { return _publish; }
  const std::vector<std::string>& retain() const { return _retain; }
  const std::vector<std::string>& subscribe() const { return _subscribe; }
  const std::vector<RefusedScope>& refused() const { return _refused; }
  bool empty() const { return _publish.empty() && _retain.empty() && _subscribe.empty(); }

 private:
  std::vector<std::string> _publish;
  std::vector<std::string> _retain;
  std::vector<std::string> _subscribe;
  std::vector<RefusedScope> _refused;
};

}  // namespace lugh::client
