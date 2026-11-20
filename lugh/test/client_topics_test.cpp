//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "lugh/client/topics.h"

using namespace lugh::client;

namespace {

TopicGrants grants(std::vector<std::string> scopes, std::string_view subject = {}) { return TopicGrants::parse(scopes, subject); }

}  // namespace

// The grammar's meaning, from TODO/2026-11-04-oauth.md, "Topic scopes, for Lir", and MQTT 5.0
// section 4.7: `pub` is a PUBLISH without the retain flag to a topic the filter matches.
TEST(ClientTopics, PubLetsAClientPublishToWhatItsFilterMatches) {
  const auto granted = grants({"lir:pub:a/+", "lir:pub:b/#"});
  EXPECT_TRUE(may_publish(granted, "a/x", false));
  EXPECT_TRUE(may_publish(granted, "b", false));
  EXPECT_TRUE(may_publish(granted, "b/x/y", false));
  EXPECT_FALSE(may_publish(granted, "a/x/y", false));
  EXPECT_FALSE(may_publish(granted, "a", false));
  EXPECT_FALSE(may_publish(granted, "c", false));
}

// `retain` is a PUBLISH with the retain flag, and neither action implies the other.
TEST(ClientTopics, RetainAndPubAreSeparateGrants) {
  const auto publish_only = grants({"lir:pub:a/#"});
  EXPECT_TRUE(may_publish(publish_only, "a/x", false));
  EXPECT_FALSE(may_publish(publish_only, "a/x", true));
  const auto retain_only = grants({"lir:retain:a/#"});
  EXPECT_TRUE(may_publish(retain_only, "a/x", true));
  EXPECT_FALSE(may_publish(retain_only, "a/x", false));
}

// A topic name has no wildcard and at least one character (section 4.7.3), whatever is granted.
TEST(ClientTopics, NoGrantLetsAClientPublishToWhatIsNotATopicName) {
  const auto granted = grants({"lir:pub:#", "lir:retain:#"});
  for (const auto* topic : {"", "a/+", "a/#", "+", "#"}) {
    EXPECT_FALSE(may_publish(granted, topic, false)) << topic;
    EXPECT_FALSE(may_publish(granted, topic, true)) << topic;
  }
}

// Section 4.7.2: a filter whose first level is a wildcard does not match a topic starting '$'.
TEST(ClientTopics, AWildcardFirstLevelNeverReachesDollarTopics) {
  EXPECT_FALSE(may_publish(grants({"lir:pub:#"}), "$SYS/x", false));
  EXPECT_FALSE(may_publish(grants({"lir:pub:+/x"}), "$SYS/x", false));
  EXPECT_TRUE(may_publish(grants({"lir:pub:$SYS/#"}), "$SYS/x", false));
  EXPECT_FALSE(may_subscribe(grants({"lir:sub:#"}), "$SYS/#"));
  EXPECT_TRUE(may_subscribe(grants({"lir:sub:$SYS/#"}), "$SYS/x"));
}

// `{sub}` is the token's subject: one client's grant is not another's.
TEST(ClientTopics, TheSubjectsLevelIsTheSubjectsOwn) {
  const auto alice = grants({"lir:pub:devices/{sub}/#", "lir:sub:devices/{sub}/#"}, "alice");
  EXPECT_TRUE(may_publish(alice, "devices/alice/state", false));
  EXPECT_FALSE(may_publish(alice, "devices/bob/state", false));
  EXPECT_TRUE(may_subscribe(alice, "devices/alice/+"));
  EXPECT_FALSE(may_subscribe(alice, "devices/+/state"));
}

// `sub` is a SUBSCRIBE whose filter the granted one covers: every topic it matches, the
// granted filter matches too.
TEST(ClientTopics, SubLetsAClientSubscribeToWhatItsFilterCovers) {
  const auto hash = grants({"lir:sub:a/#"});
  for (const auto* filter : {"a", "a/b", "a/+", "a/+/c", "a/#"}) EXPECT_TRUE(may_subscribe(hash, filter)) << filter;
  for (const auto* filter : {"b", "#", "+/b", "+"}) EXPECT_FALSE(may_subscribe(hash, filter)) << filter;

  const auto plus = grants({"lir:sub:a/+"});
  EXPECT_TRUE(may_subscribe(plus, "a/b"));
  EXPECT_TRUE(may_subscribe(plus, "a/+"));
  EXPECT_FALSE(may_subscribe(plus, "a/#"));
  EXPECT_FALSE(may_subscribe(plus, "a/b/c"));
  EXPECT_FALSE(may_subscribe(plus, "a"));
}

// A shared subscription is checked by the filter inside `$share/<group>/`; the group is the
// client's to choose.
TEST(ClientTopics, ASharedSubscriptionIsCheckedByItsFilter) {
  const auto granted = grants({"lir:sub:a/#"});
  EXPECT_TRUE(may_subscribe(granted, "$share/workers/a/b"));
  EXPECT_TRUE(may_subscribe(granted, "$share/other/a/#"));
  EXPECT_FALSE(may_subscribe(granted, "$share/workers/b"));
  for (const auto* malformed : {"$share/", "$share/g", "$share/g/", "$share//a", "$share/g+/a", "$share/g/a/#/b"}) {
    EXPECT_FALSE(may_subscribe(granted, malformed)) << malformed;
  }
}

TEST(ClientTopics, NoGrantLetsAClientSubscribeToWhatIsNotAFilter) {
  const auto granted = grants({"lir:sub:#"});
  for (const auto* filter : {"", "a/#/b", "a#", "a/b+"}) EXPECT_FALSE(may_subscribe(granted, filter)) << filter;
}

// Publishing and subscribing are separate grants, and no grant at all allows nothing.
TEST(ClientTopics, EachActionNeedsItsOwnGrant) {
  EXPECT_FALSE(may_subscribe(grants({"lir:pub:#", "lir:retain:#"}), "a"));
  EXPECT_FALSE(may_publish(grants({"lir:sub:#"}), "a", false));
  const auto none = grants({"openid", "lir:pub:%zz"});
  EXPECT_FALSE(may_publish(none, "a", false));
  EXPECT_FALSE(may_publish(none, "a", true));
  EXPECT_FALSE(may_subscribe(none, "a"));
}
