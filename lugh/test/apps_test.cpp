//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/apps/apps.h"

#include <gtest/gtest.h>

#include "lugh/test/fixtures/authn_rig.h"

using lugh::Fault;
using lugh::Outcome;
using namespace lugh::apps;

namespace {

App service_draft() {
  App app;
  app.name = "hub";
  app.kind = Kind::service;
  app.auth = ClientAuth::client_secret_basic;
  app.grants = kClientCredentials;
  app.audiences = {"lugh"};
  app.client_scopes = {"lugh:directory.read"};
  return app;
}

App api_draft(const std::string& prefix) {
  App app;
  app.name = prefix;
  app.kind = Kind::api;
  app.prefix = prefix;
  return app;
}

class AppsTest : public ::testing::Test {
 protected:
  Outcome<Apps::Made> create(App draft, std::shared_ptr<Apps> through = nullptr) {
    const auto apps = through ? through : rig.apps;
    return wait_for<Outcome<Apps::Made>>([&](lugh::Executor executor, auto done) { apps->create(rig.admin, draft, kTestDeadline, executor, done); });
  }

  std::optional<App> read(const std::string& client_id) {
    return read_value<std::optional<App>>([&](lugh::Executor executor, auto done) { rig.apps->app(client_id, kTestDeadline, executor, done); });
  }

  Outcome<App> replace(App app, std::optional<std::uint64_t> expected) {
    return wait_for<Outcome<App>>([&](lugh::Executor executor, auto done) { rig.apps->replace(rig.admin, app, expected, kTestDeadline, executor, done); });
  }

  Outcome<> remove(const std::string& client_id) {
    return wait_for<Outcome<>>(
        [&](lugh::Executor executor, auto done) { rig.apps->remove(rig.admin, client_id, std::nullopt, kTestDeadline, executor, done); });
  }

  lugh::directory::Group group(const std::string& name) {
    return wait_for<Outcome<lugh::directory::Group>>(
               [&](lugh::Executor executor, auto done) { rig.directory->create_group(rig.admin, name, "", kTestDeadline, executor, done); })
        .value;
  }

  AuthnRig rig;
};

}  // namespace

TEST_F(AppsTest, CreatingGivesARandomClientIdAndASecretShownOnce) {
  const auto made = create(service_draft());
  ASSERT_TRUE(made.ok()) << made.message;
  const auto& app = made.value.app;
  EXPECT_EQ(app.client_id.rfind("app_", 0), 0u);
  EXPECT_EQ(app.client_id.size(), 26u);
  EXPECT_EQ(app.version, 1u);
  ASSERT_TRUE(made.value.secret);
  EXPECT_EQ(lugh::secret_text(*made.value.secret).size(), 43u);
  ASSERT_EQ(app.secrets.size(), 1u);
  // Only the hash is kept, and the secret matches it.
  EXPECT_TRUE(lugh::authn::verify_password(made.value.secret->reveal(), app.secrets[0].hash));
  EXPECT_TRUE(rig.audited("app.create"));

  const auto other = create(service_draft());
  ASSERT_TRUE(other.ok());
  EXPECT_NE(other.value.app.client_id, app.client_id);
  EXPECT_NE(std::string(lugh::secret_text(*other.value.secret)), std::string(lugh::secret_text(*made.value.secret)));

  // Without client_secret_basic there is no secret at all.
  const auto api = create(api_draft("toms"));
  ASSERT_TRUE(api.ok()) << api.message;
  EXPECT_FALSE(api.value.secret);
  EXPECT_TRUE(api.value.app.secrets.empty());
}

TEST_F(AppsTest, ClientSecretsOnlyWherePolicyAllows) {
  auto strict = std::make_shared<Apps>(rig.store, rig.wall, rig.directory, rig.audit, test_pool(), Apps::Settings{});
  EXPECT_EQ(create(service_draft(), strict).fault, Fault::invalid);
}

TEST_F(AppsTest, ANewApplicationStartsBare) {
  auto draft = service_draft();
  draft.access = {"g"};
  EXPECT_EQ(create(draft).fault, Fault::invalid);
  draft = service_draft();
  draft.client_id = "app_mine";
  EXPECT_EQ(create(draft).fault, Fault::invalid);
}

// A scope or audience of an api's is only for an api that is registered, so a token can never
// name an audience nobody answers for.
TEST_F(AppsTest, ScopesAndAudiencesNeedARegisteredApi) {
  auto draft = service_draft();
  draft.client_scopes = {"toms:dns"};
  draft.audiences = {"toms"};
  EXPECT_EQ(create(draft).fault, Fault::invalid);
  ASSERT_TRUE(create(api_draft("toms")).ok());
  const auto made = create(draft);
  ASSERT_TRUE(made.ok()) << made.message;

  // An api's own prefix is registered with it.
  auto own = api_draft("macha");
  own.grants = kClientCredentials;
  own.auth = ClientAuth::client_secret_basic;
  own.client_scopes = {"macha:media.read"};
  own.audiences = {"macha"};
  EXPECT_TRUE(create(own).ok());
}

// A removed application stays as a tombstone: its prefix is never taken again, so no new
// application inherits what groups were granted under it.
TEST_F(AppsTest, PrefixesAreNeverReused) {
  const auto toms = create(api_draft("toms"));
  ASSERT_TRUE(toms.ok());
  EXPECT_EQ(create(api_draft("toms")).fault, Fault::duplicate);

  ASSERT_TRUE(remove(toms.value.app.client_id).ok());
  EXPECT_TRUE(rig.audited("app.remove"));
  EXPECT_FALSE(read(toms.value.app.client_id));
  EXPECT_TRUE(read_value<std::vector<App>>([&](lugh::Executor executor, auto done) { rig.apps->apps(kTestDeadline, executor, done); }).empty());
  EXPECT_TRUE(read_value<std::vector<std::string>>([&](lugh::Executor executor, auto done) { rig.apps->prefixes(kTestDeadline, executor, done); }).empty());
  EXPECT_EQ(create(api_draft("toms")).fault, Fault::duplicate);
  // And a removed one cannot be changed or removed again.
  EXPECT_EQ(remove(toms.value.app.client_id).fault, Fault::not_found);
}

TEST_F(AppsTest, ReplaceKeepsWhatNeverChanges) {
  const auto made = create(service_draft());
  ASSERT_TRUE(made.ok());
  auto changed = made.value.app;
  changed.name = "hub, renamed";
  changed.kind = Kind::api;
  changed.prefix = "hub";
  changed.secrets.clear();
  changed.access = {"g"};
  changed.created = 7;
  const auto replaced = replace(changed, 1);
  ASSERT_TRUE(replaced.ok()) << replaced.message;
  EXPECT_EQ(replaced.value.name, "hub, renamed");
  EXPECT_EQ(replaced.value.kind, Kind::service);
  EXPECT_TRUE(replaced.value.prefix.empty());
  EXPECT_EQ(replaced.value.secrets.size(), 1u);
  EXPECT_TRUE(replaced.value.access.empty());
  EXPECT_EQ(replaced.value.created, made.value.app.created);
  EXPECT_EQ(replaced.value.version, 2u);
  EXPECT_TRUE(rig.audited("app.update"));

  // Stale versions lose; nothing changed writes nothing; a bad change is refused whole.
  EXPECT_EQ(replace(changed, 1).fault, Fault::conflict);
  EXPECT_EQ(replace(replaced.value, std::nullopt).value.version, 2u);
  auto bad = replaced.value;
  bad.grants = kAuthorizationCode;
  EXPECT_EQ(replace(bad, std::nullopt).fault, Fault::invalid);
  auto unknown = replaced.value;
  unknown.client_id = "app_nobody";
  EXPECT_EQ(replace(unknown, std::nullopt).fault, Fault::not_found);

  // Disabling is a change like any other; leaving client_secret_basic drops the secrets.
  auto disabled = replaced.value;
  disabled.state = State::disabled;
  disabled.auth = ClientAuth::tls_client_auth;
  disabled.tls_subject = "CN=hub";
  const auto after = replace(disabled, std::nullopt);
  ASSERT_TRUE(after.ok()) << after.message;
  EXPECT_EQ(after.value.state, State::disabled);
  EXPECT_TRUE(after.value.secrets.empty());
  // And there is no way back to a secret by changing the method.
  auto back = after.value;
  back.auth = ClientAuth::client_secret_basic;
  back.tls_subject.clear();
  EXPECT_EQ(replace(back, std::nullopt).fault, Fault::invalid);
}

TEST_F(AppsTest, AccessAndRoles) {
  const auto made = create(service_draft());
  ASSERT_TRUE(made.ok());
  const auto& id = made.value.app.client_id;
  const auto staff = group("staff");

  const auto access = [&](const std::string& group_id, bool allowed) {
    return wait_for<Outcome<App>>(
        [&](lugh::Executor executor, auto done) { rig.apps->access_set(rig.admin, id, group_id, allowed, kTestDeadline, executor, done); });
  };
  EXPECT_EQ(access(staff.id, true).value.access, std::vector<std::string>{staff.id});
  EXPECT_EQ(access(staff.id, true).value.version, 2u);
  EXPECT_EQ(access("nobody", true).fault, Fault::not_found);
  EXPECT_TRUE(access(staff.id, false).value.access.empty());
  EXPECT_TRUE(rig.audited("app.access.add"));

  const auto roles = [&](const std::string& group_id, std::vector<std::string> names) {
    return wait_for<Outcome<App>>(
        [&](lugh::Executor executor, auto done) { rig.apps->roles_set(rig.admin, id, group_id, names, kTestDeadline, executor, done); });
  };
  const auto mapped = roles(staff.id, {"operator", "hub", "operator"});
  ASSERT_TRUE(mapped.ok()) << mapped.message;
  EXPECT_EQ(mapped.value.roles, (std::vector<RoleMapping>{RoleMapping{staff.id, {"hub", "operator"}}}));
  EXPECT_EQ(roles(staff.id, {"bad role"}).fault, Fault::invalid);
  EXPECT_EQ(roles("nobody", {"hub"}).fault, Fault::not_found);
  EXPECT_TRUE(roles(staff.id, {}).value.roles.empty());
}

TEST_F(AppsTest, ARotatedSecretWorksForTheOverlapOnly) {
  const auto made = create(service_draft());
  ASSERT_TRUE(made.ok());
  const auto rotate = [&] {
    return wait_for<Outcome<Apps::Made>>(
        [&](lugh::Executor executor, auto done) { rig.apps->secret_rotate(rig.admin, made.value.app.client_id, kTestDeadline, executor, done); });
  };
  const auto first = rotate();
  ASSERT_TRUE(first.ok()) << first.message;
  ASSERT_EQ(first.value.app.secrets.size(), 2u);
  EXPECT_TRUE(lugh::authn::verify_password(first.value.secret->reveal(), first.value.app.secrets[0].hash));
  EXPECT_EQ(first.value.app.secrets[0].expires, 0u);
  EXPECT_TRUE(lugh::authn::verify_password(made.value.secret->reveal(), first.value.app.secrets[1].hash));
  EXPECT_EQ(first.value.app.secrets[1].expires, rig.wall.unix_ms() / 1000 + 86400);

  // A second rotation keeps only the one before it: the first secret is gone.
  const auto second = rotate();
  ASSERT_EQ(second.value.app.secrets.size(), 2u);
  EXPECT_FALSE(lugh::authn::verify_password(made.value.secret->reveal(), second.value.app.secrets[1].hash));
  EXPECT_TRUE(rig.audited("app.secret.rotate"));

  const auto api = create(api_draft("toms"));
  EXPECT_EQ(wait_for<Outcome<Apps::Made>>([&](lugh::Executor executor, auto done) {
              rig.apps->secret_rotate(rig.admin, api.value.app.client_id, kTestDeadline, executor, done);
            }).fault,
            Fault::refused);
}

// Groups may hold an application's scopes only once its api is registered.
TEST_F(AppsTest, GrantsCheckTheRegisteredPrefixes) {
  const auto staff = group("staff");
  const auto grant = [&] {
    return wait_for<Outcome<lugh::scopes::Granted>>(
        [&](lugh::Executor executor, auto done) { rig.grants->group_set(rig.admin, staff.id, {"toms:dns"}, std::nullopt, kTestDeadline, executor, done); });
  };
  EXPECT_EQ(grant().fault, Fault::invalid);
  ASSERT_TRUE(create(api_draft("toms")).ok());
  EXPECT_TRUE(grant().ok());
}
