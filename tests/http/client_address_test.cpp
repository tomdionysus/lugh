#include "http/client_address.h"

#include <gtest/gtest.h>

using lugh::http::ClientAddress;
using lugh::http::HttpRequest;
using lugh::network::Cidr;
namespace http = lugh::http;

namespace {

boost::asio::ip::address ip(const std::string& text) { return boost::asio::ip::make_address(text); }

// A node with one proxy in front of it, on 10.0.0.0/8.
ClientAddress behind_proxy() { return ClientAddress({*Cidr::parse("10.0.0.0/8")}); }

// The default: no proxy is trusted.
ClientAddress direct() { return ClientAddress({}); }

HttpRequest request_with(std::initializer_list<std::pair<std::string, std::string>> headers) {
  HttpRequest request{http::verb::get, "/", 11};
  for (const auto& [name, value] : headers) request.insert(name, value);
  return request;
}

const auto kProxy = ip("10.0.0.5");
const auto kStranger = ip("198.51.100.7");

}  // namespace

TEST(ClientAddress, WithNoTrustedProxyEveryPeerIsItself) {
  EXPECT_EQ(direct().resolve(kStranger, request_with({})), "198.51.100.7");
  EXPECT_EQ(direct().resolve(kStranger, request_with({{"X-Forwarded-For", "203.0.113.9"}})), "198.51.100.7");
  EXPECT_EQ(direct().resolve(kProxy, request_with({{"X-Forwarded-For", "203.0.113.9"}})), "10.0.0.5");
}

TEST(ClientAddress, ATrustedProxyIsBelievedAboutItsLastEntry) {
  // The browser sent the first; the proxy appended the last.
  const auto request = request_with({{"X-Forwarded-For", "6.6.6.6, 203.0.113.9"}});
  EXPECT_EQ(behind_proxy().resolve(kProxy, request), "203.0.113.9");
}

TEST(ClientAddress, OnlyTheLastOfManyForwardedEntries) {
  const auto request = request_with({{"X-Forwarded-For", "6.6.6.6, 7.7.7.7, 8.8.8.8, 203.0.113.9"}});
  EXPECT_EQ(behind_proxy().resolve(kProxy, request), "203.0.113.9");
}

TEST(ClientAddress, TheLastForwardedLineWhenThereAreSeveral) {
  const auto request = request_with({{"X-Forwarded-For", "6.6.6.6"}, {"X-Forwarded-For", "7.7.7.7,203.0.113.9 "}});
  EXPECT_EQ(behind_proxy().resolve(kProxy, request), "203.0.113.9");
}

TEST(ClientAddress, AStrangerCannotClaimAnotherAddress) {
  const auto request = request_with({{"X-Forwarded-For", "203.0.113.9"}});
  EXPECT_EQ(behind_proxy().resolve(kStranger, request), "198.51.100.7");
}

TEST(ClientAddress, ATrustedProxyWithNoHeaderIsItself) { EXPECT_EQ(behind_proxy().resolve(kProxy, request_with({})), "10.0.0.5"); }

TEST(ClientAddress, GarbageFromAProxyIsTheProxy) {
  EXPECT_EQ(behind_proxy().resolve(kProxy, request_with({{"X-Forwarded-For", "203.0.113.9, nonsense"}})), "10.0.0.5");
}

TEST(ClientAddress, MappedIpv4PeersAreIpv4) {
  EXPECT_EQ(direct().resolve(ip("::ffff:198.51.100.7"), request_with({})), "198.51.100.7");
  EXPECT_EQ(behind_proxy().resolve(ip("::ffff:10.0.0.5"), request_with({{"X-Forwarded-For", "::ffff:203.0.113.9"}})), "203.0.113.9");
}
