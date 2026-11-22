//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// What Lugh relies on of an address range, the trusted proxies' and an app password's networks,
// now that it is Dannan's listen::Prefix: Lugh's own cases, kept, as Dannan's suite does not
// cover each (lengths that split a byte, the two families never meeting).

#include <gtest/gtest.h>

#include "lugh/network/prefix.h"

using lugh::network::prefix_of;

namespace {

boost::asio::ip::address ip(const std::string& text) { return boost::asio::ip::make_address(text); }

}  // namespace

TEST(NetworkPrefix, ParsesAnIpv4Network) {
  const auto prefix = prefix_of("10.35.1.0/24");
  ASSERT_TRUE(prefix);
  EXPECT_EQ(prefix->to_string(), "10.35.1.0/24");
  EXPECT_EQ(prefix->length, 24u);
}

TEST(NetworkPrefix, ABareAddressIsOneHost) {
  EXPECT_EQ(prefix_of("10.255.0.1")->length, 32u);
  EXPECT_EQ(prefix_of("::1")->length, 128u);
}

TEST(NetworkPrefix, RefusesWhatIsNotANetwork) {
  EXPECT_FALSE(prefix_of(""));
  EXPECT_FALSE(prefix_of("router"));
  EXPECT_FALSE(prefix_of("10.0.0.0/"));
  EXPECT_FALSE(prefix_of("10.0.0.0/33"));
  EXPECT_FALSE(prefix_of("10.0.0.0/-1"));
  EXPECT_FALSE(prefix_of("10.0.0.0/8x"));
  EXPECT_FALSE(prefix_of("::/129"));
  EXPECT_FALSE(prefix_of("10.0.0.256/32"));
}

TEST(NetworkPrefix, RefusesHostBitsSet) {
  EXPECT_FALSE(prefix_of("10.0.0.1/8"));
  EXPECT_FALSE(prefix_of("10.35.1.10/24"));
  EXPECT_TRUE(prefix_of("10.35.1.10/32"));
}

TEST(NetworkPrefix, ContainsWithinThePrefix) {
  const auto site = *prefix_of("10.35.1.0/24");
  EXPECT_TRUE(site.contains(ip("10.35.1.0")));
  EXPECT_TRUE(site.contains(ip("10.35.1.255")));
  EXPECT_FALSE(site.contains(ip("10.35.2.1")));
  EXPECT_FALSE(site.contains(ip("10.34.1.1")));
}

TEST(NetworkPrefix, PrefixesThatAreNotWholeBytes) {
  const auto pool = *prefix_of("10.255.100.0/22");
  EXPECT_TRUE(pool.contains(ip("10.255.103.255")));
  EXPECT_FALSE(pool.contains(ip("10.255.104.0")));
  EXPECT_FALSE(pool.contains(ip("10.255.99.255")));
}

TEST(NetworkPrefix, ZeroPrefixContainsEveryAddressOfItsFamily) {
  const auto all = *prefix_of("0.0.0.0/0");
  EXPECT_TRUE(all.contains(ip("203.0.113.9")));
  EXPECT_FALSE(all.contains(ip("2001:db8::1")));
}

TEST(NetworkPrefix, Ipv6) {
  const auto net = *prefix_of("2001:db8::/32");
  EXPECT_TRUE(net.contains(ip("2001:db8:ffff::1")));
  EXPECT_FALSE(net.contains(ip("2001:db9::1")));
}

TEST(NetworkPrefix, MatchesAMappedIpv4AsIpv4) {
  const auto tunnel = *prefix_of("10.0.0.0/8");
  EXPECT_TRUE(tunnel.contains(ip("::ffff:10.35.1.10")));
  EXPECT_FALSE(tunnel.contains(ip("::ffff:203.0.113.9")));
}

TEST(NetworkPrefix, FamiliesNeverMatchEachOther) { EXPECT_FALSE(prefix_of("::/0")->contains(ip("10.0.0.1"))); }
