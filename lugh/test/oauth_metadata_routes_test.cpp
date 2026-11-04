//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include "lugh/oauth/metadata_routes.h"
#include "lugh/test/fixtures/authn_rig.h"
#include "lugh/test/fixtures/route_call.h"

using lugh::oauth::MetadataRoutes;
namespace http = lugh::http;

namespace {

class MetadataTest : public ::testing::Test {
 protected:
  MetadataTest() {
    keys = std::make_shared<lugh::tokens::SigningKeys>(rig.store, rig.wall, rig.audit, lugh::tokens::SigningKeys::Settings{});
    EXPECT_TRUE(wait_for<lugh::Status>([&](lugh::Executor executor, auto done) { keys->open(kTestDeadline, executor, done); }).ok);
  }

  // The routes behind a router, as the node mounts them.
  std::shared_ptr<http::HttpResponse> get(const std::string& target, MetadataRoutes::Settings settings) {
    auto router = std::make_shared<http::Router>(io.get_executor(), std::make_shared<http::Throttle>(rig.time, http::RateLimits{{1000, 1000}, {1000, 1000}}));
    MetadataRoutes routes(keys, settings);
    routes.register_routes(*router);
    const auto prefix = target.rfind("/oauth2", 0) == 0 ? "/oauth2" : "/.well-known";
    return call(io, router->middleware(prefix), http::verb::get, target).response;
  }

  boost::asio::io_context io;
  AuthnRig rig;
  std::shared_ptr<lugh::tokens::SigningKeys> keys;
};

const MetadataRoutes::Settings kIssued{"https://id.example.com", false};

}  // namespace

TEST_F(MetadataTest, TheJwksIsOpenPublicAndCached) {
  const auto response = get("/oauth2/jwks", {});
  ASSERT_EQ(response->result(), http::status::ok);
  EXPECT_EQ(response->at(http::field::cache_control), "public, max-age=300");
  const auto body = boost::json::parse(response->body()).as_object();
  ASSERT_EQ(body.at("keys").as_array().size(), 2u);
  for (const auto& key : body.at("keys").as_array()) {
    EXPECT_TRUE(key.as_object().contains("kid"));
    EXPECT_FALSE(key.as_object().contains("d"));
    EXPECT_TRUE(lugh::tokens::from_jwk(key.as_object()));
  }
}

// RFC 8414 and OpenID Connect Discovery 1.0: the same document at both paths, every URL the
// issuer's, and only what the profile allows.
TEST_F(MetadataTest, TheMetadataDocument) {
  for (const auto* path : {"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server"}) {
    const auto response = get(path, kIssued);
    ASSERT_EQ(response->result(), http::status::ok) << path;
    const auto body = boost::json::parse(response->body()).as_object();
    EXPECT_EQ(body.at("issuer"), "https://id.example.com");
    EXPECT_EQ(body.at("jwks_uri"), "https://id.example.com/oauth2/jwks");
    EXPECT_EQ(body.at("authorization_endpoint"), "https://id.example.com/oauth2/authorize");
    EXPECT_EQ(body.at("response_types_supported"), (boost::json::array{"code"}));
    EXPECT_EQ(body.at("code_challenge_methods_supported"), (boost::json::array{"S256"}));
    EXPECT_EQ(body.at("subject_types_supported"), (boost::json::array{"public"}));
    EXPECT_EQ(body.at("id_token_signing_alg_values_supported"), (boost::json::array{"ES256", "EdDSA"}));
    const auto grants = body.at("grant_types_supported").as_array();
    EXPECT_EQ(std::find(grants.begin(), grants.end(), boost::json::value("implicit")), grants.end());
    EXPECT_EQ(std::find(grants.begin(), grants.end(), boost::json::value("password")), grants.end());
    const auto methods = body.at("token_endpoint_auth_methods_supported").as_array();
    EXPECT_EQ(std::find(methods.begin(), methods.end(), boost::json::value("client_secret_basic")), methods.end());
  }
  const auto with_secrets = boost::json::parse(get("/.well-known/openid-configuration", {"https://id.example.com", true})->body());
  const auto methods = with_secrets.at("token_endpoint_auth_methods_supported").as_array();
  EXPECT_NE(std::find(methods.begin(), methods.end(), boost::json::value("client_secret_basic")), methods.end());
}

// Without an issuer there is nothing true to say: no metadata, and the JWKS still served.
TEST_F(MetadataTest, NoIssuerNoMetadata) {
  EXPECT_EQ(get("/.well-known/openid-configuration", {})->result(), http::status::not_found);
  EXPECT_EQ(get("/oauth2/jwks", {})->result(), http::status::ok);
}

TEST(Issuer, WhatCanBeOne) {
  EXPECT_TRUE(MetadataRoutes::issuer_ok("https://id.example.com"));
  EXPECT_TRUE(MetadataRoutes::issuer_ok("https://example.com/lugh"));
  for (const auto* bad : {"http://id.example.com", "https://id.example.com/", "https://id.example.com?x=1", "https://id.example.com#x", "id.example.com", ""}) {
    EXPECT_FALSE(MetadataRoutes::issuer_ok(bad)) << bad;
  }
}

// RFC 8705 section 5: with an mTLS listener, the metadata names its endpoints there.
TEST_F(MetadataTest, MtlsEndpointAliases) {
  const auto without = boost::json::parse(get("/.well-known/openid-configuration", kIssued)->body());
  EXPECT_FALSE(without.as_object().contains("mtls_endpoint_aliases"));
  EXPECT_EQ(without.at("tls_client_certificate_bound_access_tokens"), false);

  const auto with = boost::json::parse(get("/.well-known/openid-configuration", {"https://id.example.com", false, 8444})->body());
  EXPECT_EQ(with.at("mtls_endpoint_aliases").at("token_endpoint"), "https://id.example.com:8444/oauth2/token");
  EXPECT_EQ(with.at("tls_client_certificate_bound_access_tokens"), true);
  const auto methods = with.at("token_endpoint_auth_methods_supported").as_array();
  EXPECT_NE(std::find(methods.begin(), methods.end(), boost::json::value("tls_client_auth")), methods.end());

  EXPECT_EQ(MetadataRoutes::on_port("https://id.example.com:8443/lugh", 8444), "https://id.example.com:8444/lugh");
  EXPECT_EQ(MetadataRoutes::on_port("https://[2001:db8::1]:8443", 9000), "https://[2001:db8::1]:9000");
}
