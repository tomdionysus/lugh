//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// A person's own factors after enrolment (TODO/2026-11-15-self-factors.md; docs/architecture.md,
// "Adding and removing factors"): every change behind the re-authentication window, which a TOTP
// code or a WebAuthn assertion opens and the password alone does not; the sign-in's back-off on
// the proof; the last-factor rule; and only through the person's own session.

#include <gtest/gtest.h>

#include "lugh/core/encoding.h"
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
std::string text(const boost::json::value& value, std::string_view name) { return std::string(value.as_object().at(name).as_string()); }

class FactorRoutesTest : public ::testing::Test {
 protected:
  void SetUp() override {
    alice = rig.enrolled("alice");
    ASSERT_EQ(rig.sign_in("alice", kPassword).location(), "/signin/factor");
    const auto factor = rig.get("/signin/factor");
    ASSERT_EQ(rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(rig.secret)}}).status, 303u);
    // Past the step the sign-in's code used.
    rig.advance(std::chrono::seconds(30));
  }

  SigninRig::Page call(verb method, const std::string& target, const std::string& body = "{}") { return rig.json(method, target, body); }

  SigninRig::Page reauthenticate_with_code(const std::string& code) { return call(verb::post, "/api/v1/me/reauthenticate", R"({"code":")" + code + R"("})"); }

  boost::json::array factors() {
    const auto listed = rig.get("/api/v1/me/factors");
    EXPECT_EQ(listed.status, 200u) << listed.body;
    return boost::json::parse(listed.body).at("factors").as_array();
  }

  std::string id_of(const std::string& kind) {
    for (const auto& factor : factors())
      if (text(factor, "kind") == kind) return text(factor, "id");
    return {};
  }

  static std::string error_of(const SigninRig::Page& page) { return text(boost::json::parse(page.body).at("error"), "code"); }

  // An authenticator that speaks for the rig's relying party.
  static soft_authenticator::Authenticator for_lugh() {
    soft_authenticator::Authenticator out;
    out.rp_id = SigninRig::kRpId;
    out.origin = SigninRig::kIssuer;
    return out;
  }

  boost::json::object options(const std::string& purpose) {
    const auto answer = call(verb::post, "/api/v1/me/webauthn/options", R"({"purpose":")" + purpose + R"("})");
    EXPECT_EQ(answer.status, 200u) << answer.body;
    return boost::json::parse(answer.body).as_object();
  }

  // A credential registered through the API; the window must be open.
  SigninRig::Page register_key(soft_authenticator::Authenticator& key, const std::string& name) {
    const auto made = options("register");
    const auto created = key.create(raw(text(made, "challenge")));
    return call(verb::post, "/api/v1/me/factors/webauthn",
                boost::json::serialize(boost::json::object{{"name", name},
                                                           {"challenge", text(made, "challenge")},
                                                           {"client_data", b64(created.client_data_json)},
                                                           {"attestation_object", b64(created.attestation_object)}}));
  }

  // An assertion's body for /api/v1/me/reauthenticate.
  std::string assertion_body(soft_authenticator::Authenticator& key) {
    const auto asked = options("reauthenticate");
    const auto challenge = text(asked, "challenge");
    const auto got = key.get(raw(challenge));
    return boost::json::serialize(boost::json::object{{"webauthn", boost::json::object{{"challenge", challenge},
                                                                                       {"id", b64(key.credential_id())},
                                                                                       {"client_data", b64(got.client_data_json)},
                                                                                       {"authenticator_data", b64(got.authenticator_data)},
                                                                                       {"signature", b64(got.signature)}}}});
  }

  SigninRig rig;
  lugh::directory::User alice;
};

}  // namespace

TEST_F(FactorRoutesTest, YourFactorsAreListedWithoutSecrets) {
  const auto listed = factors();
  ASSERT_EQ(listed.size(), 2u);
  const auto body = rig.get("/api/v1/me/factors").body;
  EXPECT_EQ(body.find(std::string(lugh::secret_text(rig.secret))), std::string::npos);
  EXPECT_EQ(body.find(alice.id), std::string::npos);
}

// Nothing changes until a factor is proved; the window then lasts ten minutes.
TEST_F(FactorRoutesTest, AChangeNeedsTheWindowOpen) {
  const auto closed = call(verb::post, "/api/v1/me/factors/totp");
  EXPECT_EQ(closed.status, 403u);
  EXPECT_EQ(error_of(closed), "reauthentication_required");
  EXPECT_EQ(call(verb::delete_, "/api/v1/me/factors/" + id_of("recovery"), "").status, 403u);
  EXPECT_EQ(call(verb::post, "/api/v1/me/factors/recovery").status, 403u);

  const auto wrong = reauthenticate_with_code("000000");
  EXPECT_EQ(wrong.status, 403u);
  EXPECT_EQ(error_of(wrong), "refused");
  EXPECT_TRUE(rig.audited("reauth.totp.refused"));

  const auto opened = reauthenticate_with_code(rig.code_for(rig.secret));
  ASSERT_EQ(opened.status, 200u) << opened.body;
  EXPECT_EQ(boost::json::parse(opened.body).at("expires_in"), 600);
  EXPECT_TRUE(rig.audited("reauth.totp.accepted"));
  EXPECT_EQ(reauthenticate_with_code(rig.code_for(rig.secret)).status, 403u) << "a code works once";

  rig.advance(std::chrono::minutes(9));
  EXPECT_EQ(call(verb::post, "/api/v1/me/factors/recovery").status, 201u);
  rig.advance(std::chrono::minutes(1));
  EXPECT_EQ(call(verb::post, "/api/v1/me/factors/recovery").status, 403u) << "closed at ten minutes";
}

// A second TOTP factor added and confirmed, then the first removed: the person is never without one.
TEST_F(FactorRoutesTest, AddingASecondTotpAndRemovingTheFirst) {
  const auto first = id_of("totp");
  ASSERT_EQ(reauthenticate_with_code(rig.code_for(rig.secret)).status, 200u);
  const auto made = call(verb::post, "/api/v1/me/factors/totp");
  ASSERT_EQ(made.status, 201u) << made.body;
  const auto setup = boost::json::parse(made.body);
  const auto second = text(setup, "id");
  EXPECT_NE(text(setup, "uri").find("otpauth://totp/"), std::string::npos);
  // Its QR symbol, as modules row by row, for the dashboard to draw.
  const auto size = setup.at("qr").at("size").as_int64();
  EXPECT_GE(size, 21);
  EXPECT_EQ(static_cast<std::int64_t>(setup.at("qr").at("modules").as_string().size()), size * size);
  const auto secret = lugh::text_secret(text(setup, "secret"));

  EXPECT_EQ(call(verb::post, "/api/v1/me/factors/totp/" + second + "/confirm", R"({"code":"000000"})").status, 409u);
  ASSERT_EQ(call(verb::post, "/api/v1/me/factors/totp/" + second + "/confirm", R"({"code":")" + rig.code_for(secret) + R"("})").status, 204u);
  std::size_t confirmed = 0;
  for (const auto& factor : factors()) confirmed += text(factor, "kind") == "totp" && factor.at("confirmed").as_bool() ? 1 : 0;
  EXPECT_EQ(confirmed, 2u);

  ASSERT_EQ(call(verb::delete_, "/api/v1/me/factors/" + first, "").status, 204u);
  EXPECT_TRUE(rig.audited("factor.remove"));
  // The last one stays while policy needs a second factor.
  const auto last = call(verb::delete_, "/api/v1/me/factors/" + second, "");
  EXPECT_EQ(last.status, 409u);
  EXPECT_EQ(error_of(last), "refused");
  EXPECT_EQ(call(verb::delete_, "/api/v1/me/factors/totp-nothing", "").status, 404u);
  EXPECT_EQ(call(verb::delete_, "/api/v1/me/factors/nonsense", "").status, 404u);

  // And the new one signs in.
  rig.jar.clear();
  rig.advance(std::chrono::seconds(30));
  ASSERT_EQ(rig.sign_in("alice", kPassword).location(), "/signin/factor");
  const auto factor = rig.get("/signin/factor");
  EXPECT_EQ(rig.post("/signin/factor", {{"csrf", factor.csrf()}, {"code", rig.code_for(secret)}}).status, 303u);
}

TEST_F(FactorRoutesTest, NewRecoveryCodesReplaceTheOld) {
  ASSERT_EQ(reauthenticate_with_code(rig.code_for(rig.secret)).status, 200u);
  const auto made = call(verb::post, "/api/v1/me/factors/recovery");
  ASSERT_EQ(made.status, 201u) << made.body;
  EXPECT_EQ(boost::json::parse(made.body).at("codes").as_array().size(), 10u);
  for (const auto& factor : factors())
    if (text(factor, "kind") == "recovery") {
      EXPECT_EQ(factor.at("remaining"), 10);
    }
}

// The proof backs off as a wrong code at sign-in does: a stolen session is no faster a way to guess.
TEST_F(FactorRoutesTest, GuessingTheCodeBacksOff) {
  lugh::authn::Authenticator::Settings defaults;
  for (std::uint32_t i = 0; i < defaults.account.free_failures; ++i) ASSERT_EQ(reauthenticate_with_code("000000").status, 403u) << i;
  const auto waiting = reauthenticate_with_code(rig.code_for(rig.secret));
  EXPECT_EQ(waiting.status, 429u) << "right, and still waiting";
  EXPECT_FALSE(waiting.header("Retry-After").empty());
  rig.advance(std::chrono::hours(2));
  EXPECT_EQ(reauthenticate_with_code(rig.code_for(rig.secret)).status, 200u);
}

// A recovery code stands in for a lost factor at sign-in; it does not prove one here.
TEST_F(FactorRoutesTest, NeitherARecoveryCodeNorThePasswordOpensTheWindow) {
  const auto recovery = std::string(lugh::secret_text(rig.recovery.front()));
  EXPECT_EQ(reauthenticate_with_code(recovery).status, 403u);
  EXPECT_EQ(call(verb::post, "/api/v1/me/reauthenticate", R"({"password":"correct horse battery"})").status, 400u);
  EXPECT_EQ(call(verb::post, "/api/v1/me/reauthenticate", "{}").status, 400u);
  EXPECT_EQ(call(verb::post, "/api/v1/me/factors/recovery").status, 403u);
}

// Only through the person's own session: a request with no session is not theirs.
TEST_F(FactorRoutesTest, OnlyThroughYourOwnSession) {
  rig.jar.clear();
  EXPECT_EQ(rig.get("/api/v1/me/factors").status, 401u);
  EXPECT_EQ(rig.send(verb::post, "/api/v1/me/reauthenticate", R"({"code":"000000"})", {{"Content-Type", "application/json"}}).status, 401u);
}

// A passkey added after enrolment, renamed, and then proving the person on its own.
TEST_F(FactorRoutesTest, AddingAPasskeyAfterEnrolment) {
  EXPECT_EQ(call(verb::post, "/api/v1/me/webauthn/options", R"({"purpose":"register"})").status, 403u) << "registering is a change";
  ASSERT_EQ(reauthenticate_with_code(rig.code_for(rig.secret)).status, 200u);

  const auto made = options("register");
  EXPECT_EQ(text(made.at("user"), "id"), b64(alice.id)) << "the user handle is the id, as at enrolment";
  EXPECT_EQ(text(made.at("authenticatorSelection"), "userVerification"), "required");
  EXPECT_TRUE(made.at("excludeCredentials").as_array().empty());

  auto key = for_lugh();
  const auto registered = register_key(key, "laptop");
  ASSERT_EQ(registered.status, 201u) << registered.body;
  const auto added = boost::json::parse(registered.body);
  EXPECT_EQ(text(added, "kind"), "webauthn");
  EXPECT_EQ(text(added, "name"), "laptop");
  EXPECT_TRUE(rig.audited("factor.webauthn.register"));
  EXPECT_EQ(register_key(key, "again").status, 409u) << "a credential is registered once";
  EXPECT_EQ(options("register").at("excludeCredentials").as_array().size(), 1u);

  const auto renamed = call(verb::patch, "/api/v1/me/factors/" + text(added, "id"), R"({"name":"work laptop"})");
  ASSERT_EQ(renamed.status, 200u) << renamed.body;
  EXPECT_EQ(text(boost::json::parse(renamed.body), "name"), "work laptop");
  EXPECT_TRUE(rig.audited("factor.webauthn.rename"));
  EXPECT_EQ(call(verb::patch, "/api/v1/me/factors/" + text(added, "id"), R"({"name":""})").status, 400u);
  EXPECT_EQ(call(verb::patch, "/api/v1/me/factors/" + id_of("totp"), R"({"name":"x"})").status, 404u) << "only a credential has a name";

  // Once the window has closed, the key alone opens it again; its assertion works once.
  rig.advance(std::chrono::minutes(11));
  EXPECT_EQ(call(verb::post, "/api/v1/me/factors/recovery").status, 403u);
  const auto body = assertion_body(key);
  const auto proved = call(verb::post, "/api/v1/me/reauthenticate", body);
  ASSERT_EQ(proved.status, 200u) << proved.body;
  EXPECT_TRUE(rig.audited("reauth.webauthn.accepted"));
  EXPECT_EQ(call(verb::post, "/api/v1/me/reauthenticate", body).status, 403u) << "a challenge is used once";
  EXPECT_EQ(call(verb::post, "/api/v1/me/factors/recovery").status, 201u);

  // And the passkey signs in alone, as one made at enrolment does.
  rig.jar.clear();
  const auto form = rig.get("/signin");
  const auto asked =
      rig.send(verb::post, "/signin/webauthn/options", R"({"purpose":"passkey"})", {{"Content-Type", "application/json"}, {"X-CSRF-Token", form.csrf()}});
  ASSERT_EQ(asked.status, 200u) << asked.body;
  const auto challenge = text(boost::json::parse(asked.body), "challenge");
  const auto got = key.get(raw(challenge));
  const auto signed_in = rig.post("/signin/webauthn", {{"csrf", form.csrf()},
                                                       {"purpose", "passkey"},
                                                       {"challenge", challenge},
                                                       {"id", b64(key.credential_id())},
                                                       {"user_handle", b64(alice.id)},
                                                       {"client_data", b64(got.client_data_json)},
                                                       {"authenticator_data", b64(got.authenticator_data)},
                                                       {"signature", b64(got.signature)}});
  ASSERT_EQ(signed_in.status, 303u) << signed_in.body;
  EXPECT_EQ(text(boost::json::parse(rig.get("/api/v1/me").body).at("session"), "acr"), "urn:lugh:acr:phr");
}

// An assertion by a key that is not the person's, or for a challenge issued to another session,
// proves nothing.
TEST_F(FactorRoutesTest, AForeignKeyOrChallengeProvesNothing) {
  auto stranger = for_lugh();
  const auto refused = call(verb::post, "/api/v1/me/reauthenticate", assertion_body(stranger));
  EXPECT_EQ(refused.status, 403u);
  EXPECT_TRUE(rig.audited("reauth.webauthn.refused"));

  const auto other_session = rig.challenges->issue("me:another-sid");
  const auto got = stranger.get(other_session);
  const auto body = boost::json::serialize(boost::json::object{{"webauthn", boost::json::object{{"challenge", b64(other_session)},
                                                                                                {"id", b64(stranger.credential_id())},
                                                                                                {"client_data", b64(got.client_data_json)},
                                                                                                {"authenticator_data", b64(got.authenticator_data)},
                                                                                                {"signature", b64(got.signature)}}}});
  EXPECT_EQ(call(verb::post, "/api/v1/me/reauthenticate", body).status, 403u);
}
