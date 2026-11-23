//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// lugh::client::ApiClient, P10.5 (TODO/2026-11-14-p10-plan.md): a call to /api/v1 by method and
// path, with the access token (Bearer, or DPoP with a proof the node's checker takes, RFC 9449
// section 7), a JSON body and If-Match for a write; the answer's status, body and ETag; the API's
// one error shape (lugh/http/api_json.h) as Lugh's faults, by the code a client branches on.

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>

#include "dannan/test/fixtures/stepped_time.h"
#include "lugh/client/api_client.h"
#include "lugh/oauth/dpop.h"
#include "lugh/test/fixtures/recording_https.h"

using namespace lugh::client;
using dannan::identity::Secret;

namespace {

constexpr std::uint64_t kNow = 1'800'000'000;
constexpr const char* kBase = "https://lugh.example";

boost::json::object error(const char* code, const char* message) { return {{"error", {{"code", code}, {"message", message}}}}; }

class ApiTest : public ::testing::Test {
 protected:
  ApiClient api(std::shared_ptr<const dannan::identity::SigningKey> key = nullptr) {
    return ApiClient(kBase, std::make_shared<Secret>(lugh::byte_span("at-1")), https, wall, std::move(key));
  }

  lugh::Outcome<ApiAnswer> call(ApiClient& client, ApiCall one) {
    std::optional<lugh::Outcome<ApiAnswer>> out;
    client.call(std::move(one), std::chrono::seconds(5), io.get_executor(), [&](lugh::Outcome<ApiAnswer> got) { out = std::move(got); });
    io.restart();
    io.run();
    return std::move(*out);
  }

  std::string url(const std::string& path) const { return std::string(kBase) + "/api/v1" + path; }

  boost::asio::io_context io;
  dannan::test::SteppedWall wall{kNow * 1000};
  RecordingHttps https;
};

}  // namespace

TEST_F(ApiTest, AClientNeedsAnHttpsBaseAndAToken) {
  EXPECT_THROW(ApiClient("http://lugh.example", std::make_shared<Secret>(lugh::byte_span("at-1")), https, wall), std::invalid_argument);
  EXPECT_THROW(ApiClient(kBase, nullptr, https, wall), std::invalid_argument);
  auto client = api();
  EXPECT_THROW(client.use_token(nullptr), std::invalid_argument);
  EXPECT_EQ(call(client, {"GET", "users", std::nullopt, ""}).fault, lugh::Fault::invalid);
}

TEST_F(ApiTest, ACallCarriesTheTokenAndReadsTheAnswer) {
  auto client = api();
  https.answer(url("/users/u1"), RecordingHttps::json(200, {{"id", "u1"}, {"name", "alice"}}, "\"3\""));
  const auto read = call(client, {"GET", "/users/u1", std::nullopt, ""});
  ASSERT_TRUE(read.ok()) << read.message;
  EXPECT_EQ(read.value.status, 200u);
  EXPECT_EQ(read.value.etag, "\"3\"");
  EXPECT_EQ(read.value.body.at("name").as_string(), "alice");
  EXPECT_EQ(https.sent()[0].method, "GET");
  EXPECT_EQ(https.header(0, "Authorization"), "Bearer at-1");
  EXPECT_TRUE(https.header(0, "If-Match").empty());
  EXPECT_TRUE(https.sent()[0].body.empty());

  // A refreshed token replaces the old.
  client.use_token(std::make_shared<Secret>(lugh::byte_span("at-2")));
  ASSERT_TRUE(call(client, {"GET", "/users/u1", std::nullopt, ""}).ok());
  EXPECT_EQ(https.header(1, "Authorization"), "Bearer at-2");
}

TEST_F(ApiTest, AWriteCarriesItsBodyAndTheEtagItRead) {
  auto client = api();
  https.answer(url("/users/u1"), RecordingHttps::json(200, {{"id", "u1"}}, "\"4\""));
  const auto written = call(client, {"PATCH", "/users/u1", boost::json::value{{"display_name", "Alice"}}, "\"3\""});
  ASSERT_TRUE(written.ok()) << written.message;
  EXPECT_EQ(written.value.etag, "\"4\"");
  EXPECT_EQ(https.sent()[0].method, "PATCH");
  EXPECT_EQ(https.header(0, "If-Match"), "\"3\"");
  EXPECT_EQ(https.sent()[0].content_type, "application/json");
  EXPECT_EQ(boost::json::parse(https.sent()[0].body).at("display_name").as_string(), "Alice");

  // A delete answers with no body.
  RecordingHttps::Response none;
  none.status = 204;
  https.answer(url("/groups/g1"), none);
  const auto removed = call(client, {"DELETE", "/groups/g1", std::nullopt, "*"});
  ASSERT_TRUE(removed.ok()) << removed.message;
  EXPECT_EQ(removed.value.status, 204u);
  EXPECT_TRUE(removed.value.body.is_null());
}

TEST_F(ApiTest, TheApisErrorsAreLughsFaults) {
  auto client = api();
  const auto fault_for = [&](unsigned status, const boost::json::value& body) {
    https.answer(url("/users/u1"), status, body);
    return call(client, {"GET", "/users/u1", std::nullopt, ""});
  };
  const auto missing = fault_for(404, error("not_found", "no such user"));
  EXPECT_EQ(missing.fault, lugh::Fault::not_found);
  EXPECT_EQ(missing.message, "not_found: no such user");
  EXPECT_EQ(fault_for(412, error("changed", "the record has changed")).fault, lugh::Fault::conflict);
  EXPECT_EQ(fault_for(409, error("duplicate", "that name is taken")).fault, lugh::Fault::duplicate);
  EXPECT_EQ(fault_for(409, error("refused", "the last factor")).fault, lugh::Fault::refused);
  EXPECT_EQ(fault_for(400, error("invalid", "name is required")).fault, lugh::Fault::invalid);
  EXPECT_EQ(fault_for(428, error("if_match_required", "send If-Match")).fault, lugh::Fault::invalid);
  EXPECT_EQ(fault_for(401, error("unauthorized", "no token")).fault, lugh::Fault::refused);
  EXPECT_EQ(fault_for(500, error("failed", "the request could not be completed")).fault, lugh::Fault::failed);
  EXPECT_EQ(fault_for(503, error("unavailable", "a part of the directory could not be reached")).fault, lugh::Fault::unavailable);
  EXPECT_EQ(fault_for(503, error("timed_out", "no answer within the deadline")).fault, lugh::Fault::timed_out);
  EXPECT_EQ(fault_for(503, error("cancelled", "the request was cancelled")).fault, lugh::Fault::cancelled);
  EXPECT_EQ(fault_for(503, error("busy", "every work thread is taken")).fault, lugh::Fault::unavailable);
  const auto bare = fault_for(403, boost::json::value());
  EXPECT_EQ(bare.fault, lugh::Fault::refused);
  EXPECT_EQ(bare.message.rfind("status 403", 0), 0u);
  HttpsResponse garbled;
  garbled.status = 200;
  garbled.content_type = "application/json";
  garbled.body = "{not json";
  https.answer(url("/users/u1"), garbled);
  EXPECT_EQ(call(client, {"GET", "/users/u1", std::nullopt, ""}).fault, lugh::Fault::invalid) << "a reply that cannot be read";
  https.forget_answers();
  EXPECT_EQ(call(client, {"GET", "/users/u1", std::nullopt, ""}).fault, lugh::Fault::unavailable);
}

// RFC 9449 section 7: a token bound to a key goes as `DPoP <token>`, with a proof for the method and
// the URL without its query, carrying the token's hash; the node's checker takes it.
TEST_F(ApiTest, ABoundTokenCarriesAProofTheNodeTakes) {
  dannan::test::SteppedTime time;
  lugh::oauth::DpopChecker checker{time, wall};
  const auto key = std::make_shared<SigningKey>(SigningKey::generate(SigningAlgorithm::ed25519));
  auto client = api(key);
  https.answer(url("/users?limit=5"), 200, boost::json::array{});
  ASSERT_TRUE(call(client, {"GET", "/users?limit=5", std::nullopt, ""}).ok());
  EXPECT_EQ(https.header(0, "Authorization"), "DPoP at-1");
  const auto checked = checker.check(https.header(0, "DPoP"), "GET", url("/users"), "at-1");
  ASSERT_TRUE(checked.ok()) << checked.message;
  EXPECT_EQ(checked.value.jkt, lugh::oauth::jwk_thumbprint({"", SigningAlgorithm::ed25519, key->public_key()}));
}
