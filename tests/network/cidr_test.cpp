#include "network/cidr.h"

#include <gtest/gtest.h>

using lugh::network::Cidr;

namespace {

boost::asio::ip::address ip(const std::string& text) { return boost::asio::ip::make_address(text); }

}  // namespace

TEST(Cidr, ParsesAnIpv4Network) {
  const auto cidr = Cidr::parse("10.35.1.0/24");
  ASSERT_TRUE(cidr);
  EXPECT_EQ(cidr->to_string(), "10.35.1.0/24");
  EXPECT_EQ(cidr->prefix(), 24u);
}

TEST(Cidr, ABareAddressIsOneHost) {
  EXPECT_EQ(Cidr::parse("10.255.0.1")->prefix(), 32u);
  EXPECT_EQ(Cidr::parse("::1")->prefix(), 128u);
}

TEST(Cidr, RefusesWhatIsNotANetwork) {
  EXPECT_FALSE(Cidr::parse(""));
  EXPECT_FALSE(Cidr::parse("router"));
  EXPECT_FALSE(Cidr::parse("10.0.0.0/"));
  EXPECT_FALSE(Cidr::parse("10.0.0.0/33"));
  EXPECT_FALSE(Cidr::parse("10.0.0.0/-1"));
  EXPECT_FALSE(Cidr::parse("10.0.0.0/8x"));
  EXPECT_FALSE(Cidr::parse("::/129"));
  EXPECT_FALSE(Cidr::parse("10.0.0.256/32"));
}

TEST(Cidr, RefusesHostBitsSet) {
  EXPECT_FALSE(Cidr::parse("10.0.0.1/8"));
  EXPECT_FALSE(Cidr::parse("10.35.1.10/24"));
  EXPECT_TRUE(Cidr::parse("10.35.1.10/32"));
}

TEST(Cidr, ContainsWithinThePrefix) {
  const auto site = *Cidr::parse("10.35.1.0/24");
  EXPECT_TRUE(site.contains(ip("10.35.1.0")));
  EXPECT_TRUE(site.contains(ip("10.35.1.255")));
  EXPECT_FALSE(site.contains(ip("10.35.2.1")));
  EXPECT_FALSE(site.contains(ip("10.34.1.1")));
}

TEST(Cidr, PrefixesThatAreNotWholeBytes) {
  const auto pool = *Cidr::parse("10.255.100.0/22");
  EXPECT_TRUE(pool.contains(ip("10.255.103.255")));
  EXPECT_FALSE(pool.contains(ip("10.255.104.0")));
  EXPECT_FALSE(pool.contains(ip("10.255.99.255")));
}

TEST(Cidr, ZeroPrefixContainsEveryAddressOfItsFamily) {
  const auto all = *Cidr::parse("0.0.0.0/0");
  EXPECT_TRUE(all.contains(ip("203.0.113.9")));
  EXPECT_FALSE(all.contains(ip("2001:db8::1")));
}

TEST(Cidr, Ipv6) {
  const auto net = *Cidr::parse("2001:db8::/32");
  EXPECT_TRUE(net.contains(ip("2001:db8:ffff::1")));
  EXPECT_FALSE(net.contains(ip("2001:db9::1")));
}

TEST(Cidr, MatchesAMappedIpv4AsIpv4) {
  const auto tunnel = *Cidr::parse("10.0.0.0/8");
  EXPECT_TRUE(tunnel.contains(ip("::ffff:10.35.1.10")));
  EXPECT_FALSE(tunnel.contains(ip("::ffff:203.0.113.9")));
}

TEST(Cidr, FamiliesNeverMatchEachOther) { EXPECT_FALSE(Cidr::parse("::/0")->contains(ip("10.0.0.1"))); }
