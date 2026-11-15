//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The sign-in pages' WebAuthn (TODO/2026-11-15-p11-webauthn.md, W4), driven as the script drives
// them: the options fetched with the visitor's CSRF token, the ceremony run by the software
// authenticator, and its result posted as a form.

#include <gtest/gtest.h>

#include "lugh/core/encoding.h"
#include "lugh/signin/html.h"
#include "lugh/test/fixtures/signin_rig.h"
#include "lugh/test/fixtures/soft_authenticator.h"

using lugh::http::verb;

namespace {

constexpr const char* kPassword = "correct horse battery";

std::string b64(std::string_view bytes) { return lugh::encoding::base64url({reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()}); }
std::string b64(const std::vector<std::uint8_t>& bytes) { return lugh::encoding::base64url(bytes); }
std::string raw(std::string_view text) {
  const auto bytes = lugh::encoding::base64url_decode(text);
  return bytes ? std::string(bytes->begin(), bytes->end()) : std::string();
}

// An authenticator that speaks for the rig's relying party.
soft_authenticator::Authenticator for_lugh() {
  soft_authenticator::Authenticator out;
  out.rp_id = SigninRig::kRpId;
  out.origin = SigninRig::kIssuer;
  return out;
}

SigninRig::Page fetch_options(SigninRig& rig, const std::string& csrf, const std::string& purpose) {
  return rig.send(verb::post, "/signin/webauthn/options", R"({"purpose":")" + purpose + R"("})",
                  {{"Content-Type", "application/json"}, {"X-CSRF-Token", csrf}});
}

boost::json::object options(SigninRig& rig, const std::string& csrf, const std::string& purpose) {
  const auto answer = fetch_options(rig, csrf, purpose);
  EXPECT_EQ(answer.status, 200u) << answer.body;
  return boost::json::parse(answer.body).as_object();
}

std::string text(const boost::json::object& object, std::string_view name) { return std::string(object.at(name).as_string()); }

// The acr of the session the rig's browser holds.
std::string session_acr(SigninRig& rig) {
  const auto me = rig.get("/api/v1/me");
  return text(boost::json::parse(me.body).at("session").as_object(), "acr");
}

}  // namespace

// From an enrolment link to a passkey, then signing in with it alone, with no name typed.
TEST(SigninWebAuthn, EnrolAPasskeyThenSignInWithItAlone) {
  SigninRig rig;
  const auto alice = rig.person("alice");
  const auto link = wait_for<lugh::Outcome<lugh::Secret>>([&](lugh::Executor executor, auto done) {
                      rig.links->issue(rig.admin, alice.id, kTestDeadline, executor, done);
                    }).value;
  const std::string token(lugh::secret_text(link));
  const auto set = rig.get("/signin/enrol/" + token);
  ASSERT_EQ(rig.post("/signin/enrol/" + token, {{"csrf", set.csrf()}, {"password", kPassword}, {"password_again", kPassword}}).location(),
            "/signin/enrol/totp");

  const auto enrol = rig.get("/signin/enrol/totp");
  ASSERT_EQ(enrol.status, 200u);
  EXPECT_TRUE(enrol.says("data-webauthn=\"enrol\""));
  EXPECT_TRUE(enrol.says("<script src=\"/signin/webauthn.js\" defer></script>"));
  EXPECT_EQ(enrol.header("Content-Security-Policy"), lugh::signin::kPagePolicy);

  const auto made_options = options(rig, enrol.csrf(), "enrol");
  EXPECT_EQ(text(made_options.at("rp").as_object(), "id"), SigninRig::kRpId);
  EXPECT_EQ(text(made_options.at("user").as_object(), "id"), b64(alice.id)) << "the user handle is the id, never the name";
  EXPECT_EQ(text(made_options.at("authenticatorSelection").as_object(), "userVerification"), "required");
  EXPECT_EQ(text(made_options.at("authenticatorSelection").as_object(), "residentKey"), "required");
  EXPECT_EQ(text(made_options, "attestation"), "none");
  EXPECT_EQ(made_options.at("pubKeyCredParams").as_array().size(), 3u);

  auto authenticator = for_lugh();
  const auto created = authenticator.create(raw(text(made_options, "challenge")));
  const auto enrolled = rig.post("/signin/webauthn", {{"csrf", enrol.csrf()},
                                                      {"purpose", "enrol"},
                                                      {"challenge", text(made_options, "challenge")},
                                                      {"id", b64(authenticator.credential_id())},
                                                      {"client_data", b64(created.client_data_json)},
                                                      {"attestation_object", b64(created.attestation_object)},
                                                      {"name", "laptop"}});
  ASSERT_EQ(enrolled.status, 200u) << enrolled.body;
  EXPECT_TRUE(enrolled.says("recovery codes"));
  EXPECT_EQ(session_acr(rig), "urn:lugh:acr:phr");

  // Another browser: no name, no password, the passkey alone.
  rig.jar.clear();
  const auto form = rig.get("/signin");
  EXPECT_TRUE(form.says("data-webauthn=\"passkey\""));
  const auto get_options = options(rig, form.csrf(), "passkey");
  EXPECT_EQ(text(get_options, "rpId"), SigninRig::kRpId);
  EXPECT_EQ(text(get_options, "userVerification"), "required");
  EXPECT_TRUE(get_options.at("allowCredentials").as_array().empty()) << "a discoverable credential names the user";
  const auto proof = authenticator.get(raw(text(get_options, "challenge")));
  const std::map<std::string, std::string> result{{"csrf", form.csrf()},
                                                  {"purpose", "passkey"},
                                                  {"challenge", text(get_options, "challenge")},
                                                  {"id", b64(authenticator.credential_id())},
                                                  {"client_data", b64(proof.client_data_json)},
                                                  {"authenticator_data", b64(proof.authenticator_data)},
                                                  {"signature", b64(proof.signature)},
                                                  {"user_handle", b64(alice.id)}};
  const auto signed_in = rig.post("/signin/webauthn", result);
  ASSERT_EQ(signed_in.status, 303u) << signed_in.body;
  EXPECT_EQ(signed_in.location(), "/signin/done");
  EXPECT_EQ(session_acr(rig), "urn:lugh:acr:phr");
  EXPECT_TRUE(rig.audited("signin.complete"));

  // The same ceremony posted again: its challenge is spent.
  const auto again = rig.post("/signin/webauthn", result);
  EXPECT_EQ(again.status, 401u);
  EXPECT_TRUE(again.says("Start again"));
}

// A password, then a security key instead of a code.
TEST(SigninWebAuthn, ACredentialAsTheSecondFactor) {
  SigninRig rig;
  const auto alice = rig.enrolled("alice");
  auto authenticator = for_lugh();
  authenticator.user_verified = false;
  const auto created = authenticator.create("registration challenge, 32 bytes");
  lugh::webauthn::Expected expected{SigninRig::kRpId, {SigninRig::kIssuer}, "registration challenge, 32 bytes", false};
  ASSERT_TRUE(wait_for<lugh::Outcome<lugh::authn::FactorInfo>>([&](lugh::Executor executor, auto done) {
                rig.factors->webauthn_register(
                    rig.admin, alice.id, "key", expected, lugh::Bytes(created.client_data_json.begin(), created.client_data_json.end()),
                    lugh::Bytes(created.attestation_object.begin(), created.attestation_object.end()), kTestDeadline, executor, done);
              }).ok());

  ASSERT_EQ(rig.sign_in("alice", kPassword).location(), "/signin/factor");
  const auto factor = rig.get("/signin/factor");
  EXPECT_TRUE(factor.says("data-webauthn=\"factor\""));
  const auto get_options = options(rig, factor.csrf(), "factor");
  const auto& allowed = get_options.at("allowCredentials").as_array();
  ASSERT_EQ(allowed.size(), 1u);
  EXPECT_EQ(text(allowed[0].as_object(), "id"), b64(authenticator.credential_id()));

  const auto proof = authenticator.get(raw(text(get_options, "challenge")));
  const auto signed_in = rig.post("/signin/webauthn", {{"csrf", factor.csrf()},
                                                       {"purpose", "factor"},
                                                       {"challenge", text(get_options, "challenge")},
                                                       {"id", b64(authenticator.credential_id())},
                                                       {"client_data", b64(proof.client_data_json)},
                                                       {"authenticator_data", b64(proof.authenticator_data)},
                                                       {"signature", b64(proof.signature)}});
  ASSERT_EQ(signed_in.status, 303u) << signed_in.body;
  EXPECT_EQ(signed_in.location(), "/signin/done");
  EXPECT_EQ(session_acr(rig), "urn:lugh:acr:phr");
}

TEST(SigninWebAuthn, TheScriptAndWhatGuardsItsEndpoints) {
  SigninRig rig;
  const auto script = rig.get("/signin/webauthn.js");
  ASSERT_EQ(script.status, 200u);
  EXPECT_EQ(script.header("Content-Type"), "text/javascript; charset=utf-8");
  EXPECT_TRUE(script.says("navigator.credentials"));

  const auto form = rig.get("/signin");
  EXPECT_EQ(fetch_options(rig, "forged", "passkey").status, 403u) << "without the visitor's token";
  EXPECT_EQ(rig.send(verb::post, "/signin/webauthn/options", R"({"purpose":"passkey"})", {{"Content-Type", "application/json"}}).status, 403u);
  EXPECT_EQ(fetch_options(rig, form.csrf(), "factor").status, 409u) << "no password given yet";
  EXPECT_EQ(fetch_options(rig, form.csrf(), "enrol").status, 409u) << "not enrolling";
  EXPECT_EQ(fetch_options(rig, form.csrf(), "anything").status, 400u);

  // A challenge Lugh never issued, or issued to another visitor.
  auto authenticator = for_lugh();
  const auto proof = authenticator.get("a challenge Lugh never issued...");
  const auto forged = rig.post("/signin/webauthn", {{"csrf", form.csrf()},
                                                    {"purpose", "passkey"},
                                                    {"challenge", b64(std::string("a challenge Lugh never issued..."))},
                                                    {"id", b64(authenticator.credential_id())},
                                                    {"client_data", b64(proof.client_data_json)},
                                                    {"authenticator_data", b64(proof.authenticator_data)},
                                                    {"signature", b64(proof.signature)},
                                                    {"user_handle", b64(std::string("someone"))}});
  EXPECT_EQ(forged.status, 401u);
  EXPECT_TRUE(forged.says("Start again"));
}
