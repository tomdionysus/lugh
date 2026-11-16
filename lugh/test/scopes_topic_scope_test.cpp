//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/scopes/scope.h"

#include <gtest/gtest.h>

#include "lugh/scopes/topic_scope.h"

using namespace lugh::scopes;

namespace {

TopicLevel text(std::string value) { return TopicLevel{std::move(value), false}; }
TopicLevel subject() { return TopicLevel{"", true}; }

}  // namespace

// The grammar, from TODO/2026-11-04-oauth.md, "Topic scopes, for Lir", as the maintainer decided it.
TEST(TopicScope, ActionsAndPlainFilters) {
  const auto pub = decode_topic("lir:pub:sensors/kitchen/temperature");
  ASSERT_TRUE(pub);
  EXPECT_EQ(pub->action, TopicAction::pub);
  EXPECT_EQ(pub->levels, (std::vector<TopicLevel>{text("sensors"), text("kitchen"), text("temperature")}));
  EXPECT_EQ(decode_topic("lir:sub:#")->action, TopicAction::sub);
  EXPECT_EQ(decode_topic("lir:retain:state/+")->action, TopicAction::retain);
  EXPECT_FALSE(decode_topic("lir:publish:a"));
  EXPECT_FALSE(decode_topic("lir:a"));
  EXPECT_FALSE(decode_topic("mqtt:sub:a"));
  EXPECT_FALSE(decode_topic("lir:sub:"));
}

// MQTT 5.0 section 4.7: '/' separates levels, empty levels are levels, '+' is one whole level,
// '#' the whole last.
TEST(TopicScope, MqttFilterRules) {
  EXPECT_EQ(decode_topic("lir:sub:a//b")->levels, (std::vector<TopicLevel>{text("a"), text(""), text("b")}));
  EXPECT_EQ(decode_topic("lir:sub:/a")->levels, (std::vector<TopicLevel>{text(""), text("a")}));
  EXPECT_EQ(decode_topic("lir:sub:a/")->levels, (std::vector<TopicLevel>{text("a"), text("")}));
  EXPECT_TRUE(decode_topic("lir:sub:+/+/#"));
  EXPECT_TRUE(decode_topic("lir:sub:$lir/#"));
  EXPECT_FALSE(decode_topic("lir:sub:a/#/b"));
  EXPECT_FALSE(decode_topic("lir:sub:a#"));
  EXPECT_FALSE(decode_topic("lir:sub:a+/b"));
  EXPECT_FALSE(decode_topic("lir:sub:a/b+"));
}

// '+' is literal under strict decoding: the wildcard, never a space.
TEST(TopicScope, PlusIsTheWildcardNotASpace) {
  EXPECT_EQ(decode_topic("lir:sub:a/+")->levels.back(), text("+"));
  EXPECT_FALSE(decode_topic("lir:sub:a+b"));
  // Encoded or not, '+' inside a level is no MQTT filter.
  EXPECT_FALSE(decode_topic("lir:sub:a%2Bb"));
  EXPECT_EQ(decode_topic("lir:sub:%2B")->levels.back(), text("+"));
}

// A level may hold '"' or '\', which a scope token may not (RFC 6749 section 3.3), so they are
// written encoded and the scope still decodes to what it was (fuzz_scope, 2026-11-16).
TEST(TopicScope, AQuoteOrBackslashInALevelIsWrittenEncoded) {
  const auto decoded = decode_topic("lir:pub:say%22hi%22/a%5Cb");
  ASSERT_TRUE(decoded);
  EXPECT_EQ(decoded->levels, (std::vector<TopicLevel>{text("say\"hi\""), text("a\\b")}));
  const auto encoded = encode_topic(*decoded);
  ASSERT_TRUE(encoded);
  EXPECT_TRUE(well_formed(*encoded)) << *encoded;
  EXPECT_EQ(decode_topic(*encoded), decoded);
}

TEST(TopicScope, PercentEncodingIsStrict) {
  EXPECT_EQ(decode_topic("lir:pub:room%20one/lamp")->levels.front(), text("room one"));
  EXPECT_EQ(decode_topic("lir:pub:caf%C3%A9")->levels.front(), text("caf\xc3\xa9"));
  EXPECT_EQ(decode_topic("lir:pub:100%25")->levels.front(), text("100%"));
  // A malformed escape is refused, never passed through.
  EXPECT_FALSE(decode_topic("lir:pub:100%"));
  EXPECT_FALSE(decode_topic("lir:pub:%zz"));
  EXPECT_FALSE(decode_topic("lir:pub:%4"));
  // A '/' cannot be smuggled into a level.
  EXPECT_FALSE(decode_topic("lir:pub:a%2Fb"));
  // Nor U+0000, nor any control, nor bytes that are not UTF-8.
  EXPECT_FALSE(decode_topic("lir:pub:a%00b"));
  EXPECT_FALSE(decode_topic("lir:pub:a%0Ab"));
  EXPECT_FALSE(decode_topic("lir:pub:a%C2%85"));
  EXPECT_FALSE(decode_topic("lir:pub:%FF"));
  // A raw space is not a scope at all.
  EXPECT_FALSE(decode_topic("lir:pub:room one"));
}

// {sub} is a whole level and the only substitution; {client} was dropped (the maintainer, 2026-11-04).
TEST(TopicScope, SubjectSubstitution) {
  EXPECT_EQ(decode_topic("lir:pub:devices/{sub}/#")->levels, (std::vector<TopicLevel>{text("devices"), subject(), text("#")}));
  EXPECT_EQ(decode_topic("lir:sub:{sub}")->levels, std::vector<TopicLevel>{subject()});
  EXPECT_FALSE(decode_topic("lir:pub:devices/{client}/#"));
  EXPECT_FALSE(decode_topic("lir:pub:devices/x{sub}"));
  EXPECT_FALSE(decode_topic("lir:pub:devices/{sub}x"));
  EXPECT_FALSE(decode_topic("lir:pub:devices/{"));
  // A literal brace is encoded, and is then text, not a substitution.
  EXPECT_EQ(decode_topic("lir:pub:%7Bsub%7D")->levels.front(), text("{sub}"));
}

TEST(TopicScope, EncodingRoundTrips) {
  const TopicScope scope{TopicAction::retain, {text("home"), text("living room"), text("{sub}"), subject(), text("caf\xc3\xa9 100%"), text("+"), text("#")}};
  const auto encoded = encode_topic(scope);
  ASSERT_TRUE(encoded);
  EXPECT_EQ(*encoded, "lir:retain:home/living%20room/%7Bsub%7D/{sub}/caf%C3%A9%20100%25/+/#");
  EXPECT_EQ(decode_topic(*encoded), scope);

  EXPECT_EQ(encode_topic({TopicAction::sub, {text("$lir"), text("#")}}), "lir:sub:$lir/#");
  EXPECT_EQ(encode_topic({TopicAction::pub, {text(""), text("a"), text("")}}), "lir:pub:/a/");
}

TEST(TopicScope, EncodingRefusesWhatIsNotAFilter) {
  EXPECT_FALSE(encode_topic({TopicAction::sub, {}}));
  EXPECT_FALSE(encode_topic({TopicAction::sub, {text("")}}));
  EXPECT_FALSE(encode_topic({TopicAction::sub, {text("a/b")}}));
  EXPECT_FALSE(encode_topic({TopicAction::sub, {text("#"), text("a")}}));
  EXPECT_FALSE(encode_topic({TopicAction::sub, {text("a#")}}));
  EXPECT_FALSE(encode_topic({TopicAction::sub, {text(std::string("a\0b", 3))}}));
  EXPECT_FALSE(encode_topic({TopicAction::sub, {TopicLevel{"x", true}}}));
  // Under the scope cap: a long topic is refused, which keeps tokens small.
  EXPECT_FALSE(encode_topic({TopicAction::sub, {text(std::string(1100, 'a'))}}));
}
