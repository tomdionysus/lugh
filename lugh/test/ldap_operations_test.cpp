//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <algorithm>

#include "lugh/ldap/authz.h"
#include "lugh/ldap/operations.h"
#include "lugh/ldap/tree.h"
#include "lugh/scopes/scope.h"
#include "lugh/test/fixtures/authn_rig.h"

using namespace lugh::ldap;
using lugh::Executor;
using lugh::Outcome;
using lugh::Secret;
using lugh::directory::Group;
using lugh::directory::Kind;
using lugh::directory::User;

namespace {

constexpr const char* kBase = "dc=example,dc=com";
constexpr const char* kPassword = "correct horse battery";

Filter present(const std::string& attribute) {
  Filter out;
  out.kind = Filter::Kind::present;
  out.attribute = attribute;
  return out;
}

Filter equal(const std::string& attribute, const std::string& value) {
  Filter out;
  out.kind = Filter::Kind::equal;
  out.attribute = attribute;
  out.value = value;
  return out;
}

Filter all_of(std::vector<Filter> children) {
  Filter out;
  out.kind = Filter::Kind::all_of;
  out.children = std::move(children);
  return out;
}

std::vector<std::string> dns_of(const SearchAnswer& answer) {
  std::vector<std::string> out;
  for (const auto& entry : answer.entries) out.push_back(entry.dn);
  return out;
}

std::vector<std::string> values_of(const SearchEntry& entry, const std::string& attribute) {
  for (const auto& one : entry.attributes) {
    if (one.type == attribute) return one.values;
  }
  return {};
}

bool has_attribute(const SearchEntry& entry, const std::string& attribute) {
  return std::any_of(entry.attributes.begin(), entry.attributes.end(), [&](const Attribute& one) { return one.type == attribute; });
}

class LdapTest : public ::testing::Test {
 protected:
  void SetUp() override {
    tree = std::make_shared<Tree>(rig.directory, Tree::Settings{kBase, "/home/{name}", "/bin/bash", "staff"});
    binder = std::make_shared<Binder>(tree, rig.directory, rig.authenticator, rig.app_passwords, rig.grants, rig.audit);
    Operations::Settings settings;
    settings.vendor_version = "1.2.3";
    settings.extensions = {kWhoAmIOid};
    settings.controls = {kPagedResultsOid};
    settings.most_results = 5;
    operations = std::make_shared<Operations>(tree, settings);
    alice = rig.enrolled("alice");
    staff = group("staff", "The staff");
    add(staff, alice);
  }

  Group group(const std::string& name, const std::string& description = "") {
    return wait_for<Outcome<Group>>(
               [&](Executor executor, auto done) { rig.directory->create_group(rig.admin, name, description, kTestDeadline, executor, done); })
        .value;
  }

  void add(const Group& to, const User& user) {
    ASSERT_TRUE(
        wait_for<Outcome<>>([&](Executor executor, auto done) { rig.directory->add_member(rig.admin, to.id, user.id, kTestDeadline, executor, done); }).ok());
  }

  User service(const std::string& name) {
    return wait_for<Outcome<User>>([&](Executor executor, auto done) {
             rig.directory->create_user(rig.admin, {Kind::service, name, "", name, "", ""}, kTestDeadline, executor, done);
           })
        .value;
  }

  void grant(const Group& to, std::vector<std::string> scopes) {
    ASSERT_TRUE(wait_for<Outcome<lugh::scopes::Granted>>([&](Executor executor, auto done) {
                  rig.grants->group_set(rig.admin, to.id, scopes, std::nullopt, kTestDeadline, executor, done);
                }).ok());
  }

  // A bound identity that holds these scopes, for the tests about what comes after a bind.
  Bound as(const User& user, std::vector<std::string> scopes) {
    Bound out;
    out.dn = tree->dn_of(user);
    out.caller = lugh::http::Caller{lugh::http::Caller::Kind::user, user.id, std::move(scopes)};
    return out;
  }
  Bound reader() { return as(alice, {lugh::scopes::kDirectoryRead}); }

  SearchRequest request(const std::string& base, Scope scope, Filter filter = present("objectclass"), std::vector<std::string> attributes = {}) {
    SearchRequest out;
    out.base = base;
    out.scope = scope;
    out.filter = std::move(filter);
    out.attributes = std::move(attributes);
    return out;
  }

  SearchAnswer search(const std::optional<Bound>& bound, SearchRequest asked, std::optional<PagedResults> paged = std::nullopt) {
    return wait_for<SearchAnswer>([&](Executor executor, auto done) { operations->search(bound, std::move(asked), paged, executor, done); });
  }

  Result compare(const std::optional<Bound>& bound, const std::string& entry, const std::string& attribute, const std::string& value) {
    return wait_for<Result>([&](Executor executor, auto done) { operations->compare(bound, {entry, attribute, value}, executor, done); });
  }

  BindAnswer bind(const std::string& name, const std::string& password, const std::string& address = "192.0.2.5") {
    return wait_for<BindAnswer>([&](Executor executor, auto done) { binder->bind(name, lugh::text_secret(password), address, kTestDeadline, executor, done); });
  }

  void password_policy() {
    ASSERT_TRUE(wait_for<Outcome<>>([&](Executor executor, auto done) {
                  rig.policies->global_set(rig.admin, lugh::authn::Assurance::pwd, kTestDeadline, executor, done);
                }).ok());
  }

  std::string app_password(const User& user, std::vector<std::string> scopes = {}, std::vector<std::string> networks = {}) {
    auto made = wait_for<Outcome<lugh::authn::AppPasswords::Made>>(
        [&](Executor executor, auto done) { rig.app_passwords->create(rig.admin, user.id, "device", scopes, networks, kTestDeadline, executor, done); });
    EXPECT_TRUE(made.ok()) << made.message;
    last_app_password_id = made.value.info.id;
    return std::string(lugh::secret_text(made.value.password));
  }

  std::optional<Bound> current(const Bound& bound) {
    const auto read = wait_for<Outcome<std::optional<Bound>>>([&](Executor executor, auto done) { binder->current(bound, kTestDeadline, executor, done); });
    EXPECT_TRUE(read.ok());
    return read.value;
  }

  std::string dn(const std::string& leaf) { return leaf + "," + kBase; }

  AuthnRig rig;
  std::shared_ptr<Tree> tree;
  std::shared_ptr<Binder> binder;
  std::shared_ptr<Operations> operations;
  User alice;
  Group staff;
  std::string last_app_password_id;
};

}  // namespace

TEST_F(LdapTest, WhereADnFalls) {
  const auto place = [&](const std::string& text) { return tree->locate(*parse_dn(text)); };
  EXPECT_EQ(place("DC=Example,DC=Com").kind, Place::Kind::base);
  EXPECT_EQ(place("ou=People,dc=example,dc=com").kind, Place::Kind::people);
  EXPECT_EQ(place("ou=services,dc=example,dc=com").kind, Place::Kind::services);
  EXPECT_EQ(place("ou=groups,dc=example,dc=com").kind, Place::Kind::groups);
  const auto leaf = place("uid=Alice,ou=people,dc=example,dc=com");
  EXPECT_EQ(leaf.kind, Place::Kind::person);
  EXPECT_EQ(leaf.name, "alice");
  EXPECT_EQ(place("uid=x,ou=services,dc=example,dc=com").kind, Place::Kind::service);
  EXPECT_EQ(place("cn=x,ou=groups,dc=example,dc=com").kind, Place::Kind::group);

  for (const auto* outside : {"dc=other,dc=com", "ou=other,dc=example,dc=com", "cn=x,ou=people,dc=example,dc=com", "uid=x,ou=groups,dc=example,dc=com",
                              "uid=a,uid=b,ou=people,dc=example,dc=com", "uid=x,dc=example,dc=com"}) {
    EXPECT_EQ(place(outside).kind, Place::Kind::outside) << outside;
  }
  Tree::Settings bad;
  bad.base_dn = "not a dn";
  EXPECT_THROW(Tree(rig.directory, bad), std::invalid_argument);
  bad.base_dn = "";
  EXPECT_THROW(Tree(rig.directory, bad), std::invalid_argument);
}

// TODO/2026-11-04-ldap.md, "Entries".
TEST_F(LdapTest, APersonsEntry) {
  auto changed = lugh::directory::UserChange{};
  changed.display_name = "Alice Smith";
  changed.given_name = "Alice";
  changed.family_name = "Smith";
  ASSERT_TRUE(wait_for<Outcome<User>>([&](Executor executor, auto done) {
                rig.directory->update_user(rig.admin, alice.id, changed, std::nullopt, kTestDeadline, executor, done);
              }).ok());

  const auto found = search(reader(), request(dn("uid=alice,ou=people"), Scope::base, present("objectclass"), {"*", "+"}));
  ASSERT_EQ(found.result.code, ResultCode::success) << found.result.message;
  ASSERT_EQ(found.entries.size(), 1u);
  const auto& entry = found.entries[0];
  EXPECT_EQ(entry.dn, dn("uid=alice,ou=people"));
  auto classes = values_of(entry, "objectClass");
  std::sort(classes.begin(), classes.end());
  EXPECT_EQ(classes, (std::vector<std::string>{"inetOrgPerson", "organizationalPerson", "person", "top"})) << "no posixAccount without a number";
  EXPECT_EQ(values_of(entry, "uid"), (std::vector<std::string>{"alice"}));
  EXPECT_EQ(values_of(entry, "cn"), (std::vector<std::string>{"Alice Smith"}));
  EXPECT_EQ(values_of(entry, "displayName"), (std::vector<std::string>{"Alice Smith"}));
  EXPECT_EQ(values_of(entry, "givenName"), (std::vector<std::string>{"Alice"}));
  EXPECT_EQ(values_of(entry, "sn"), (std::vector<std::string>{"Smith"}));
  EXPECT_EQ(values_of(entry, "mail"), (std::vector<std::string>{"alice@example.com"}));
  EXPECT_EQ(values_of(entry, "memberOf"), (std::vector<std::string>{dn("cn=staff,ou=groups")}));
  EXPECT_EQ(values_of(entry, "entryUUID"), (std::vector<std::string>{alice.id}));
  // 2026-10-18T00:00:00Z, the rig's clock, give or take the steps enrolment took.
  EXPECT_EQ(values_of(entry, "createTimestamp").at(0).rfind("20261018", 0), 0u);
  EXPECT_EQ(values_of(entry, "createTimestamp").at(0).back(), 'Z');
  EXPECT_FALSE(has_attribute(entry, "userPassword"));
}

TEST_F(LdapTest, UntilAFamilyNameIsSetSnIsTheDisplayName) {
  const auto found = search(reader(), request(dn("uid=alice,ou=people"), Scope::base));
  ASSERT_EQ(found.entries.size(), 1u);
  EXPECT_EQ(values_of(found.entries[0], "sn"), values_of(found.entries[0], "cn"));
  EXPECT_FALSE(has_attribute(found.entries[0], "givenName"));
}

TEST_F(LdapTest, AGroupsEntryAgreesWithItsMembers) {
  const auto bot = service("bot");
  add(staff, bot);
  const auto found = search(reader(), request(dn("cn=staff,ou=groups"), Scope::base, present("objectclass"), {"*", "+"}));
  ASSERT_EQ(found.entries.size(), 1u);
  const auto& entry = found.entries[0];
  EXPECT_EQ(values_of(entry, "cn"), (std::vector<std::string>{"staff"}));
  EXPECT_EQ(values_of(entry, "description"), (std::vector<std::string>{"The staff"}));
  auto members = values_of(entry, "member");
  std::sort(members.begin(), members.end());
  EXPECT_EQ(members, (std::vector<std::string>{dn("uid=alice,ou=people"), dn("uid=bot,ou=services")}));
  EXPECT_EQ(values_of(entry, "entryUUID"), (std::vector<std::string>{staff.id}));

  // And each member's says the same of it.
  const auto of_bot = search(reader(), request(dn("uid=bot,ou=services"), Scope::base));
  EXPECT_EQ(values_of(of_bot.entries.at(0), "memberOf"), (std::vector<std::string>{dn("cn=staff,ou=groups")}));
}

TEST_F(LdapTest, ServicesLiveApartFromPeople) {
  service("bot");
  const auto people = search(reader(), request(dn("ou=people"), Scope::one));
  EXPECT_EQ(dns_of(people), (std::vector<std::string>{dn("uid=alice,ou=people")}));
  const auto services = search(reader(), request(dn("ou=services"), Scope::one));
  EXPECT_EQ(dns_of(services), (std::vector<std::string>{dn("uid=bot,ou=services")}));
  // Not found under the wrong container.
  EXPECT_EQ(search(reader(), request(dn("uid=bot,ou=people"), Scope::base)).result.code, ResultCode::no_such_object);
  EXPECT_EQ(search(reader(), request(dn("uid=alice,ou=services"), Scope::base)).result.code, ResultCode::no_such_object);
}

TEST_F(LdapTest, TheScopes) {
  const auto base = search(reader(), request(kBase, Scope::base));
  EXPECT_EQ(dns_of(base), (std::vector<std::string>{kBase}));
  EXPECT_EQ(values_of(base.entries.at(0), "dc"), (std::vector<std::string>{"example"}));

  EXPECT_EQ(dns_of(search(reader(), request(kBase, Scope::one))), (std::vector<std::string>{dn("ou=people"), dn("ou=services"), dn("ou=groups")}));
  EXPECT_EQ(dns_of(search(reader(), request(kBase, Scope::subtree))),
            (std::vector<std::string>{kBase, dn("ou=people"), dn("ou=services"), dn("ou=groups"), dn("uid=alice,ou=people")}))
      << "at most_results";
  EXPECT_EQ(dns_of(search(reader(), request(dn("ou=groups"), Scope::subtree))), (std::vector<std::string>{dn("ou=groups"), dn("cn=staff,ou=groups")}));
  EXPECT_TRUE(search(reader(), request(dn("uid=alice,ou=people"), Scope::one)).entries.empty()) << "a leaf has no children";
  EXPECT_EQ(search(reader(), request(dn("uid=alice,ou=people"), Scope::one)).result.code, ResultCode::success);
  EXPECT_EQ(dns_of(search(reader(), request(dn("uid=alice,ou=people"), Scope::subtree))), (std::vector<std::string>{dn("uid=alice,ou=people")}));
}

// RFC 3673, RFC 4511 section 4.5.1.8.
TEST_F(LdapTest, TheAttributesAskedFor) {
  const auto with = [&](std::vector<std::string> attributes) {
    return search(reader(), request(dn("uid=alice,ou=people"), Scope::base, present("objectclass"), attributes)).entries.at(0);
  };
  EXPECT_TRUE(has_attribute(with({}), "uid"));
  EXPECT_FALSE(has_attribute(with({}), "entryUUID")) << "operational, so only when asked";
  EXPECT_TRUE(has_attribute(with({"*"}), "uid"));
  EXPECT_FALSE(has_attribute(with({"+"}), "uid"));
  EXPECT_TRUE(has_attribute(with({"+"}), "entryUUID"));
  EXPECT_TRUE(has_attribute(with({"+"}), "lughEntryVersion"));
  EXPECT_TRUE(has_attribute(with({"ENTRYUUID"}), "entryUUID")) << "by name, whatever the case";
  const auto named = with({"mail", "nothing"});
  ASSERT_EQ(named.attributes.size(), 1u);
  EXPECT_EQ(named.attributes[0].type, "mail");
  EXPECT_TRUE(with({"1.1"}).attributes.empty());

  auto types = request(dn("uid=alice,ou=people"), Scope::base);
  types.types_only = true;
  const auto typed = search(reader(), types).entries.at(0);
  EXPECT_TRUE(has_attribute(typed, "uid"));
  EXPECT_TRUE(values_of(typed, "uid").empty());
}

TEST_F(LdapTest, FiltersOverTheTree) {
  rig.person("bob");
  rig.person("carol");
  const auto matching = [&](Filter filter) { return dns_of(search(reader(), request(dn("ou=people"), Scope::one, std::move(filter)))); };
  Filter prefix;
  prefix.kind = Filter::Kind::substring;
  prefix.attribute = "uid";
  prefix.initial = "BO";
  EXPECT_EQ(matching(prefix), (std::vector<std::string>{dn("uid=bob,ou=people")}));

  Filter either;
  either.kind = Filter::Kind::any_of;
  either.children = {equal("cn", "bob"), equal("cn", "carol")};
  EXPECT_EQ(matching(either), (std::vector<std::string>{dn("uid=bob,ou=people"), dn("uid=carol,ou=people")}));

  EXPECT_EQ(matching(equal("memberof", dn("cn=STAFF,ou=groups"))), (std::vector<std::string>{dn("uid=alice,ou=people")}));
  // Undefined is not a match, and neither is its negation.
  Filter unsupported;
  unsupported.kind = Filter::Kind::unsupported;
  EXPECT_TRUE(matching(unsupported).empty());
  Filter not_unsupported;
  not_unsupported.kind = Filter::Kind::negated;
  not_unsupported.children = {unsupported};
  EXPECT_TRUE(matching(not_unsupported).empty());
}

// Pinned lookups find the same as a scan would, and stay inside the base.
TEST_F(LdapTest, AFilterThatPinsOneEntry) {
  rig.person("bob");
  const auto bob_dn = dn("uid=bob,ou=people");
  const auto from_base = [&](Filter filter, Scope scope = Scope::subtree) { return dns_of(search(reader(), request(kBase, scope, std::move(filter)))); };
  EXPECT_EQ(from_base(equal("uid", "BOB")), (std::vector<std::string>{bob_dn}));
  EXPECT_EQ(from_base(equal("mail", "Bob@Example.com")), (std::vector<std::string>{bob_dn}));
  EXPECT_EQ(from_base(all_of({equal("uid", "bob"), present("mail")})), (std::vector<std::string>{bob_dn}));
  EXPECT_TRUE(from_base(all_of({equal("uid", "bob"), equal("mail", "wrong@example.com")})).empty()) << "the rest of the filter still counts";
  EXPECT_TRUE(from_base(equal("uid", "nobody")).empty());
  EXPECT_EQ(from_base(equal("entryuuid", staff.id)), (std::vector<std::string>{dn("cn=staff,ou=groups")}));
  EXPECT_EQ(from_base(equal("entryuuid", alice.id)), (std::vector<std::string>{dn("uid=alice,ou=people")}));
  EXPECT_TRUE(from_base(equal("uid", "bob"), Scope::one).empty()) << "a person is not one level below the base";
  EXPECT_TRUE(dns_of(search(reader(), request(dn("ou=services"), Scope::subtree, equal("uid", "bob")))).empty()) << "nor under services";
  EXPECT_EQ(dns_of(search(reader(), request(dn("ou=groups"), Scope::one, equal("cn", "STAFF")))), (std::vector<std::string>{dn("cn=staff,ou=groups")}));
  // A cn from the whole tree may be a person's too, so that one is not a group's alone.
  EXPECT_EQ(from_base(equal("cn", "bob")), (std::vector<std::string>{bob_dn}));
}

TEST_F(LdapTest, TheSizeLimit) {
  for (const auto* name : {"bob", "carol", "dave", "erin", "fred"}) rig.person(name);
  auto limited = request(dn("ou=people"), Scope::one);
  limited.size_limit = 2;
  const auto two = search(reader(), limited);
  EXPECT_EQ(two.entries.size(), 2u);
  EXPECT_EQ(two.result.code, ResultCode::size_limit_exceeded);

  // The server's own, for a client that asks for more or for no limit.
  limited.size_limit = 0;
  const auto server = search(reader(), limited);
  EXPECT_EQ(server.entries.size(), 5u);
  EXPECT_EQ(server.result.code, ResultCode::size_limit_exceeded);

  // Exactly as many as match is no excess.
  auto fits = request(dn("ou=groups"), Scope::one);
  fits.size_limit = 1;
  EXPECT_EQ(search(reader(), fits).result.code, ResultCode::success);
}

// RFC 2696: past the server's limit, a page at a time.
TEST_F(LdapTest, PagingThroughEverything) {
  std::vector<std::string> expected;
  for (const auto* name : {"bob", "carol", "dave", "erin", "fred", "gina", "hank"}) rig.person(name);
  for (const auto* name : {"alice", "bob", "carol", "dave", "erin", "fred", "gina", "hank"}) expected.push_back(dn(std::string("uid=") + name + ",ou=people"));

  std::vector<std::string> seen;
  std::string cookie;
  int pages = 0;
  do {
    const auto page = search(reader(), request(dn("ou=people"), Scope::one), PagedResults{3, cookie});
    ASSERT_EQ(page.result.code, ResultCode::success) << page.result.message;
    ASSERT_TRUE(page.paged);
    for (const auto& one : dns_of(page)) seen.push_back(one);
    cookie = page.paged->cookie;
    ++pages;
    ASSERT_LT(pages, 10);
  } while (!cookie.empty());
  EXPECT_EQ(seen, expected);
  EXPECT_EQ(pages, 3);

  // A page size past the server's is cut to it, and is still only a page.
  const auto large = search(reader(), request(dn("ou=people"), Scope::one), PagedResults{100, ""});
  EXPECT_EQ(large.entries.size(), 5u);
  EXPECT_EQ(large.result.code, ResultCode::success);
  EXPECT_FALSE(large.paged->cookie.empty());

  // Size zero with a cookie gives it up.
  const auto given_up = search(reader(), request(dn("ou=people"), Scope::one), PagedResults{0, large.paged->cookie});
  EXPECT_EQ(given_up.result.code, ResultCode::success);
  EXPECT_TRUE(given_up.entries.empty());
  EXPECT_TRUE(given_up.paged->cookie.empty());
}

// A person removed between pages leaves the rest of them where they were.
TEST_F(LdapTest, APageTokenSurvivesAChange) {
  const auto bob = rig.person("bob");
  rig.person("carol");
  const auto first = search(reader(), request(dn("ou=people"), Scope::one), PagedResults{2, ""});
  ASSERT_EQ(dns_of(first), (std::vector<std::string>{dn("uid=alice,ou=people"), dn("uid=bob,ou=people")}));
  ASSERT_TRUE(wait_for<Outcome<>>([&](Executor executor, auto done) {
                rig.directory->remove_user(rig.admin, bob.id, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  const auto second = search(reader(), request(dn("ou=people"), Scope::one), PagedResults{2, first.paged->cookie});
  EXPECT_EQ(dns_of(second), (std::vector<std::string>{dn("uid=carol,ou=people")}));
}

TEST_F(LdapTest, TheRootDseIsForAnyone) {
  const auto root = search(std::nullopt, request("", Scope::base, present("objectclass")));
  ASSERT_EQ(root.result.code, ResultCode::success);
  ASSERT_EQ(root.entries.size(), 1u);
  const auto& entry = root.entries[0];
  EXPECT_EQ(entry.dn, "");
  EXPECT_EQ(values_of(entry, "namingContexts"), (std::vector<std::string>{kBase}));
  EXPECT_EQ(values_of(entry, "supportedLDAPVersion"), (std::vector<std::string>{"3"}));
  EXPECT_EQ(values_of(entry, "supportedExtension"), (std::vector<std::string>{kWhoAmIOid}));
  EXPECT_EQ(values_of(entry, "supportedControl"), (std::vector<std::string>{kPagedResultsOid}));
  EXPECT_EQ(values_of(entry, "vendorVersion"), (std::vector<std::string>{"1.2.3"}));
  EXPECT_FALSE(has_attribute(entry, "supportedSASLMechanisms")) << "there are none";

  EXPECT_TRUE(search(std::nullopt, request("", Scope::base, equal("uid", "x"))).entries.empty());
  EXPECT_EQ(search(std::nullopt, request("", Scope::subtree)).result.code, ResultCode::no_such_object);
}

TEST_F(LdapTest, AnonymousReadsNothingElse) {
  EXPECT_EQ(search(std::nullopt, request(kBase, Scope::base)).result.code, ResultCode::insufficient_access_rights);
  EXPECT_EQ(search(std::nullopt, request(dn("uid=alice,ou=people"), Scope::base)).result.code, ResultCode::insufficient_access_rights);
  EXPECT_EQ(compare(std::nullopt, dn("uid=alice,ou=people"), "uid", "alice").code, ResultCode::insufficient_access_rights);
}

// What may not be read is not there.
TEST_F(LdapTest, WithoutDirectoryReadOnlyYourself) {
  rig.person("bob");
  const auto own = as(alice, {});
  EXPECT_EQ(dns_of(search(own, request(dn("uid=alice,ou=people"), Scope::base))), (std::vector<std::string>{dn("uid=alice,ou=people")}));
  EXPECT_EQ(search(own, request(dn("uid=bob,ou=people"), Scope::base)).result.code, ResultCode::no_such_object);
  EXPECT_EQ(search(own, request(dn("uid=bob,ou=people"), Scope::base)).result.message,
            search(own, request(dn("uid=nobody,ou=people"), Scope::base)).result.message);
  EXPECT_EQ(search(own, request(dn("cn=staff,ou=groups"), Scope::base)).result.code, ResultCode::no_such_object);

  // Searching the people finds only them, though the tree's shape is there to search from.
  EXPECT_EQ(dns_of(search(own, request(dn("ou=people"), Scope::one))), (std::vector<std::string>{dn("uid=alice,ou=people")}));
  EXPECT_TRUE(search(own, request(kBase, Scope::subtree, equal("uid", "bob"))).entries.empty());

  EXPECT_EQ(compare(own, dn("uid=alice,ou=people"), "uid", "alice").code, ResultCode::compare_true);
  EXPECT_EQ(compare(own, dn("uid=bob,ou=people"), "uid", "bob").code, ResultCode::no_such_object);
}

TEST_F(LdapTest, ABaseThatIsNotInTheTree) {
  EXPECT_EQ(search(reader(), request("dc=other,dc=com", Scope::subtree)).result.code, ResultCode::no_such_object);
  EXPECT_EQ(search(reader(), request(dn("ou=other"), Scope::subtree)).result.code, ResultCode::no_such_object);
  EXPECT_EQ(search(reader(), request(dn("uid=nobody,ou=people"), Scope::base)).result.code, ResultCode::no_such_object);
  EXPECT_EQ(search(reader(), request("not a dn", Scope::base)).result.code, ResultCode::invalid_dn_syntax);
}

// RFC 4511 section 4.10.
TEST_F(LdapTest, Compare) {
  const auto entry = dn("uid=alice,ou=people");
  EXPECT_EQ(compare(reader(), entry, "uid", "ALICE").code, ResultCode::compare_true);
  EXPECT_EQ(compare(reader(), entry, "uid", "bob").code, ResultCode::compare_false);
  EXPECT_EQ(compare(reader(), entry, "givenName", "x").code, ResultCode::no_such_attribute);
  EXPECT_EQ(compare(reader(), entry, "userPassword", kPassword).code, ResultCode::no_such_attribute);
  EXPECT_EQ(compare(reader(), entry, "memberOf", dn("CN=staff,ou=groups")).code, ResultCode::compare_true);
  EXPECT_EQ(compare(reader(), dn("uid=nobody,ou=people"), "uid", "x").code, ResultCode::no_such_object);
  EXPECT_EQ(compare(reader(), "not a dn", "uid", "x").code, ResultCode::invalid_dn_syntax);
}

// TODO/2026-11-04-ldap.md, "What a bind proves".
TEST_F(LdapTest, AMainPasswordUnderAPasswordPolicy) {
  password_policy();
  grant(staff, {lugh::scopes::kDirectoryRead, lugh::scopes::kAuditRead});
  const auto bound = bind(dn("UID=Alice,ou=people"), kPassword);
  ASSERT_EQ(bound.result.code, ResultCode::success) << bound.result.message;
  ASSERT_TRUE(bound.bound);
  EXPECT_EQ(bound.bound->dn, dn("uid=alice,ou=people")) << "as the tree has it, not as it was typed";
  EXPECT_EQ(bound.bound->caller.id, alice.id);
  EXPECT_TRUE(bound.bound->caller.has_scope(lugh::scopes::kDirectoryRead));
  EXPECT_TRUE(bound.bound->caller.has_scope(lugh::scopes::kAuditRead));
  EXPECT_FALSE(bound.bound->app_password);
  EXPECT_TRUE(rig.audited("signin.password.accepted"));
}

// LDAP cannot carry a second factor, so a main password is not enough for one who needs it.
TEST_F(LdapTest, AMainPasswordUnderAStrongerPolicyIsRefused) {
  const auto bound = bind(dn("uid=alice,ou=people"), kPassword);
  EXPECT_EQ(bound.result.code, ResultCode::invalid_credentials);
  EXPECT_FALSE(bound.bound);
}

TEST_F(LdapTest, AnAppPasswordGetsThereInstead) {
  grant(staff, {lugh::scopes::kDirectoryRead, lugh::scopes::kDirectoryWrite});
  const auto password = app_password(alice);
  const auto bound = bind(dn("uid=alice,ou=people"), password);
  ASSERT_EQ(bound.result.code, ResultCode::success) << bound.result.message;
  EXPECT_EQ(bound.bound->app_password, last_app_password_id);
  EXPECT_EQ(bound.bound->caller.scopes, (std::vector<std::string>{lugh::scopes::kDirectoryRead})) << "read-only by default, though its owner may write";
  EXPECT_TRUE(rig.audited("ldap.bind"));
}

// Never more than its owner's own scopes, at the time of each bind.
TEST_F(LdapTest, AnAppPasswordsScopesAreCutToItsOwners) {
  grant(staff, {lugh::scopes::kDirectoryRead, lugh::scopes::kDirectoryWrite});
  const auto password = app_password(alice, {lugh::scopes::kDirectoryRead, lugh::scopes::kDirectoryWrite});
  EXPECT_EQ(bind(dn("uid=alice,ou=people"), password).bound->caller.scopes.size(), 2u);
  grant(staff, {lugh::scopes::kDirectoryRead});
  EXPECT_EQ(bind(dn("uid=alice,ou=people"), password).bound->caller.scopes, (std::vector<std::string>{lugh::scopes::kDirectoryRead}));
}

TEST_F(LdapTest, AServiceBindsWithAnAppPassword) {
  const auto bot = service("bot");
  add(staff, bot);
  grant(staff, {lugh::scopes::kDirectoryRead});
  const auto password = app_password(bot);
  const auto bound = bind(dn("uid=bot,ou=services"), password);
  ASSERT_EQ(bound.result.code, ResultCode::success) << bound.result.message;
  EXPECT_EQ(bound.bound->caller.id, bot.id);
  EXPECT_EQ(bind(dn("uid=bot,ou=people"), password).result.code, ResultCode::invalid_credentials) << "under the wrong container";
  EXPECT_EQ(bind(dn("uid=bot,ou=services"), "not it, and no shape of one").result.code, ResultCode::invalid_credentials);
}

TEST_F(LdapTest, AnAppPasswordKeepsToItsNetworks) {
  const auto password = app_password(alice, {}, {"10.0.0.0/8"});
  EXPECT_EQ(bind(dn("uid=alice,ou=people"), password, "10.1.2.3").result.code, ResultCode::success);
  EXPECT_EQ(bind(dn("uid=alice,ou=people"), password, "192.0.2.5").result.code, ResultCode::invalid_credentials);
}

// All the same to the client.
TEST_F(LdapTest, EveryRefusalLooksTheSame) {
  password_policy();
  const auto disabled = rig.enrolled("disabled");
  ASSERT_TRUE(wait_for<Outcome<User>>([&](Executor executor, auto done) {
                rig.directory->disable_user(rig.admin, disabled.id, true, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  rig.person("unenrolled");
  const auto wrong = bind(dn("uid=alice,ou=people"), "not the password");
  for (const auto& answer :
       {wrong, bind(dn("uid=nobody,ou=people"), kPassword), bind(dn("uid=disabled,ou=people"), kPassword), bind(dn("uid=unenrolled,ou=people"), kPassword),
        bind("dc=other,dc=com", kPassword), bind("not a dn", kPassword), bind("", kPassword), bind(dn("cn=staff,ou=groups"), kPassword)}) {
    EXPECT_EQ(answer.result.code, ResultCode::invalid_credentials);
    EXPECT_EQ(answer.result.message, wrong.result.message);
    EXPECT_FALSE(answer.bound);
  }
}

// RFC 4513 section 5.1.2: an empty password is not an anonymous bind that succeeded.
TEST_F(LdapTest, AnEmptyPasswordIsRefused) {
  password_policy();
  const auto empty = bind(dn("uid=alice,ou=people"), "");
  EXPECT_EQ(empty.result.code, ResultCode::inappropriate_authentication);
  EXPECT_FALSE(empty.bound);
}

// The back-off is the sign-in's: wrong guesses over LDAP stop a right one.
TEST_F(LdapTest, TheBackOffIsTheSignIns) {
  password_policy();
  lugh::authn::Authenticator::Settings defaults;
  ASSERT_EQ(bind(dn("uid=alice,ou=people"), kPassword).result.code, ResultCode::success);
  for (std::uint32_t i = 0; i < defaults.account.free_failures + 1; ++i)
    ASSERT_EQ(bind(dn("uid=alice,ou=people"), "wrong").result.code, ResultCode::invalid_credentials);
  EXPECT_EQ(bind(dn("uid=alice,ou=people"), kPassword).result.code, ResultCode::invalid_credentials);

  // An app password is no way round it, and wrong ones count.
  const auto password = app_password(alice);
  EXPECT_EQ(bind(dn("uid=alice,ou=people"), password).result.code, ResultCode::invalid_credentials);

  // And it counts at the sign-in pages' door as well: they share the account.
  const auto through_pages = wait_for<lugh::authn::Step>(
      [&](Executor executor, auto done) { rig.authenticator->password("alice", lugh::text_secret(kPassword), "192.0.2.99", kTestDeadline, executor, done); });
  EXPECT_EQ(through_pages.kind, lugh::authn::Step::Kind::wait);

  rig.advance(std::chrono::hours(2));
  EXPECT_EQ(bind(dn("uid=alice,ou=people"), kPassword).result.code, ResultCode::success);
  EXPECT_EQ(bind(dn("uid=alice,ou=people"), password).result.code, ResultCode::success);
}

// A connection outlives what it proved.
TEST_F(LdapTest, TheIdentityIsCheckedAgain) {
  grant(staff, {lugh::scopes::kDirectoryRead});
  const auto password = app_password(alice, {lugh::scopes::kDirectoryRead});
  const auto bound = bind(dn("uid=alice,ou=people"), password).bound;
  ASSERT_TRUE(bound);
  EXPECT_TRUE(current(*bound));

  grant(staff, {});
  ASSERT_TRUE(current(*bound));
  EXPECT_TRUE(current(*bound)->caller.scopes.empty()) << "its owner's scopes fell";

  ASSERT_TRUE(wait_for<Outcome<>>([&](Executor executor, auto done) {
                rig.app_passwords->revoke(rig.admin, alice.id, last_app_password_id, kTestDeadline, executor, done);
              }).ok());
  EXPECT_FALSE(current(*bound)) << "the app password was revoked";
}

TEST_F(LdapTest, AUserDisabledOrRemovedIsNoLongerBound) {
  const auto bob = rig.enrolled("bob");
  EXPECT_TRUE(current(as(bob, {})));
  ASSERT_TRUE(wait_for<Outcome<User>>([&](Executor executor, auto done) {
                rig.directory->disable_user(rig.admin, bob.id, true, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_FALSE(current(as(bob, {})));
  ASSERT_TRUE(wait_for<Outcome<>>([&](Executor executor, auto done) {
                rig.directory->remove_user(rig.admin, bob.id, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_FALSE(current(as(bob, {})));
}

// RFC 4532.
TEST_F(LdapTest, WhoAmI) {
  EXPECT_EQ(Operations::who_am_i(reader()), "dn:" + dn("uid=alice,ou=people"));
  EXPECT_EQ(Operations::who_am_i(std::nullopt), "");
}
