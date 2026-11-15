//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>

#include <thread>

#include "lugh/http/rate_limiter.h"
#include "lugh/http/tls_context.h"
#include "lugh/ldap/ldap_server.h"
#include "lugh/scopes/scope.h"
#include "lugh/test/fixtures/authn_rig.h"
#include "lugh/test/fixtures/ldap_client.h"
#include "lugh/test/fixtures/temp_directory.h"
#include "lugh/test/fixtures/test_certificate.h"

using namespace lugh::ldap;
using ldap_client::Client;
using lugh::Executor;
using lugh::Outcome;

namespace {

constexpr const char* kBase = "dc=example,dc=com";
constexpr const char* kAlice = "uid=alice,ou=people,dc=example,dc=com";
constexpr const char* kPassword = "correct horse battery";

int code(ResultCode result) { return static_cast<int>(result); }

// Real listeners on 127.0.0.1, one of each, on threads of their own, over AuthnRig.
class LdapConnectionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    alice = rig.enrolled("alice");
    ASSERT_TRUE(wait_for<Outcome<>>([&](Executor executor, auto done) {
                  rig.policies->global_set(rig.admin, lugh::authn::Assurance::pwd, kTestDeadline, executor, done);
                }).ok());
    const auto group = wait_for<Outcome<lugh::directory::Group>>([&](Executor executor, auto done) {
                         rig.directory->create_group(rig.admin, "staff", "", kTestDeadline, executor, done);
                       }).value;
    ASSERT_TRUE(wait_for<Outcome<>>([&](Executor executor, auto done) {
                  rig.directory->add_member(rig.admin, group.id, alice.id, kTestDeadline, executor, done);
                }).ok());
    ASSERT_TRUE(wait_for<Outcome<lugh::scopes::Granted>>([&](Executor executor, auto done) {
                  rig.grants->group_set(rig.admin, group.id, {lugh::scopes::kDirectoryRead, lugh::scopes::kDirectoryWrite}, std::nullopt, kTestDeadline,
                                        executor, done);
                }).ok());
  }

  void TearDown() override { stop(); }

  void start(std::chrono::milliseconds idle = std::chrono::minutes(10), std::size_t most_connections = LdapServer::kMostConnections,
             std::size_t most_pending = 8) {
    const auto certificates = std::make_shared<dannan::listen::Certificates>(
        dannan::listen::CertificatePaths{dir.write("cert.pem", pair.certificate_pem), dir.write("key.pem", pair.key_pem), {}});
    auto tree = std::make_shared<Tree>(rig.directory, [] {
      Tree::Settings settings;
      settings.base_dn = kBase;
      return settings;
    }());
    Operations::Settings settings;
    settings.vendor_version = "test";
    settings.extensions = {kStartTlsOid, kWhoAmIOid};
    settings.controls = {kPagedResultsOid};
    ConnectionParts parts;
    parts.binder = std::make_shared<Binder>(tree, rig.directory, rig.authenticator, rig.app_passwords, rig.grants, rig.audit);
    parts.operations = std::make_shared<Operations>(tree, settings);
    sessions = std::make_shared<lugh::session::Sessions>(rig.store, rig.wall, rig.directory, rig.grants, rig.audit, lugh::session::Sessions::Settings{});
    parts.writes = std::make_shared<Writes>(tree, rig.directory, sessions, rig.passwords, rig.authenticator);
    parts.certificates = certificates;
    parts.throttle = throttle;
    parts.anonymous_bind = anonymous_bind;
    parts.idle = idle;
    parts.most_pending = most_pending;
    ldaps = std::make_shared<LdapServer>(rig.logger, io, parts, true, most_connections);
    plain = std::make_shared<LdapServer>(rig.logger, io, parts, false, most_connections);
    ASSERT_TRUE(ldaps->listen("127.0.0.1", 0).ok);
    ASSERT_TRUE(plain->listen("127.0.0.1", 0).ok);
    ldaps_port = ldaps->port();
    plain_port = plain->port();
    ldaps->start();
    plain->start();
    thread = std::thread([this] { io.run(); });
  }

  void stop() {
    if (!thread.joinable()) return;
    ldaps->stop();
    plain->stop();
    io.stop();
    thread.join();
  }

  Client secure() { return Client(ldaps_port, Client::Mode::ldaps); }
  Client plaintext() { return Client(plain_port, Client::Mode::plaintext); }

  AuthnRig rig;
  lugh::directory::User alice;
  TempDirectory dir;
  TestCertificate pair;
  boost::asio::io_context io;
  std::shared_ptr<lugh::http::Throttle> throttle = std::make_shared<lugh::http::Throttle>(rig.time, lugh::http::RateLimits{{10000, 10000}, {10000, 10000}});
  std::shared_ptr<lugh::session::Sessions> sessions;
  std::shared_ptr<LdapServer> ldaps;
  std::shared_ptr<LdapServer> plain;
  bool anonymous_bind = false;
  std::uint16_t ldaps_port = 0;
  std::uint16_t plain_port = 0;
  std::thread thread;
};

}  // namespace

TEST_F(LdapConnectionTest, OverLdaps) {
  start();
  auto client = secure();
  ASSERT_TRUE(client.connected);
  const auto bound = client.bind(kAlice, kPassword);
  ASSERT_TRUE(bound);
  EXPECT_EQ(bound->code, 0) << bound->message;
  EXPECT_EQ(bound->op, ldap_client::kBindResponse);

  const auto who = client.extended(kWhoAmIOid);
  ASSERT_TRUE(who);
  EXPECT_EQ(who->code, 0);
  EXPECT_EQ(who->value, std::string("dn:") + kAlice);

  const auto found = client.search(kBase, 2, {"mail"}, ldap_client::filter_equal("uid", "alice"));
  ASSERT_TRUE(found);
  EXPECT_EQ(found->done.code, 0) << found->done.message;
  ASSERT_EQ(found->entries.size(), 1u);
  EXPECT_EQ(found->entries[0].dn, kAlice);
  EXPECT_EQ(found->entries[0].attributes.at("mail"), (std::vector<std::string>{"alice@example.com"}));

  const auto same = client.compare(kAlice, "uid", "alice");
  ASSERT_TRUE(same);
  EXPECT_EQ(same->code, code(ResultCode::compare_true));

  // RFC 4511 section 4.3: no response, and the connection closes.
  client.send_raw(client.unbind_bytes(client.next_id()));
  EXPECT_TRUE(client.closes());
}

TEST_F(LdapConnectionTest, PagedOverTheWire) {
  for (const auto* name : {"bob", "carol", "dave"}) rig.person(name);
  start();
  auto client = secure();
  ASSERT_EQ(client.bind(kAlice, kPassword)->code, 0);
  std::size_t seen = 0;
  std::string cookie;
  int pages = 0;
  do {
    const auto page = client.search("ou=people,dc=example,dc=com", 1, {"1.1"}, ldap_client::filter_present("uid"), std::make_pair(3, cookie));
    ASSERT_TRUE(page);
    ASSERT_EQ(page->done.code, 0);
    ASSERT_TRUE(page->done.cookie);
    seen += page->entries.size();
    cookie = *page->done.cookie;
    ++pages;
  } while (!cookie.empty() && pages < 10);
  EXPECT_EQ(seen, 4u);
  EXPECT_EQ(pages, 2);
}

TEST_F(LdapConnectionTest, TheRootDseBeforeAnyone) {
  start();
  const auto check = [](Client client) {
    const auto root = client.search("", 0, {"namingContexts"});
    ASSERT_TRUE(root);
    EXPECT_EQ(root->done.code, 0);
    ASSERT_EQ(root->entries.size(), 1u);
    EXPECT_EQ(root->entries[0].attributes.at("namingContexts"), (std::vector<std::string>{kBase}));
  };
  check(secure());
  check(plaintext());
}

// TODO/2026-11-04-ldap.md: plaintext carries nothing but StartTLS and the rootDSE.
TEST_F(LdapConnectionTest, PlaintextCarriesNothingElse) {
  start();
  auto client = plaintext();
  EXPECT_EQ(client.bind(kAlice, kPassword)->code, code(ResultCode::confidentiality_required));
  EXPECT_EQ(client.search(kBase, 0)->done.code, code(ResultCode::confidentiality_required));
  EXPECT_EQ(client.compare(kAlice, "uid", "alice")->code, code(ResultCode::confidentiality_required));
  EXPECT_EQ(client.extended(kWhoAmIOid)->code, code(ResultCode::confidentiality_required));
}

TEST_F(LdapConnectionTest, StartTlsOpensEverything) {
  start();
  auto client = plaintext();
  ASSERT_TRUE(client.start_tls());
  EXPECT_EQ(client.bind(kAlice, kPassword)->code, 0);
  EXPECT_EQ(client.extended(kWhoAmIOid)->value, std::string("dn:") + kAlice);

  // Once TLS is up, a second is refused, and the connection goes on.
  const auto again = client.extended(kStartTlsOid);
  ASSERT_TRUE(again);
  EXPECT_EQ(again->code, code(ResultCode::operations_error));
  EXPECT_EQ(client.extended(kWhoAmIOid)->code, 0);
}

TEST_F(LdapConnectionTest, StartTlsOnLdapsIsRefused) {
  start();
  auto client = secure();
  EXPECT_EQ(client.extended(kStartTlsOid)->code, code(ResultCode::operations_error));
}

// CVE-2011-0411's class: what follows StartTLS in plaintext is not to be acted on under TLS.
TEST_F(LdapConnectionTest, BytesAfterStartTlsAreNotActedOn) {
  start();
  auto client = plaintext();
  client.send_raw(client.extended_bytes(1, kStartTlsOid) + client.extended_bytes(2, kWhoAmIOid));
  while (const auto answer = client.read()) {
    EXPECT_NE(answer->id, 2);
    EXPECT_NE(answer->code, 0) << "StartTLS must not have been agreed to";
  }
  EXPECT_TRUE(client.closed);
}

TEST_F(LdapConnectionTest, WhatABindLeaves) {
  start();
  auto client = secure();
  ASSERT_EQ(client.bind(kAlice, kPassword)->code, 0);
  EXPECT_EQ(client.bind(kAlice, "wrong")->code, code(ResultCode::invalid_credentials));
  EXPECT_EQ(client.extended(kWhoAmIOid)->value, "") << "a failed bind leaves it anonymous";
  EXPECT_EQ(client.search(kBase, 0)->done.code, code(ResultCode::insufficient_access_rights));
  EXPECT_EQ(client.bind(kAlice, kPassword)->code, 0);
  EXPECT_EQ(client.extended(kWhoAmIOid)->value, std::string("dn:") + kAlice);
}

TEST_F(LdapConnectionTest, WhatABindRefuses) {
  start();
  auto client = secure();
  EXPECT_EQ(client.bind(kAlice, "")->code, code(ResultCode::inappropriate_authentication));

  // SASL, by hand: the client has no use for it otherwise.
  lugh::ldap::ber::Writer sasl;
  sasl.begin(0x30);
  sasl.integer(0x02, 50);
  sasl.begin(0x60);
  sasl.integer(0x02, 3);
  sasl.octets(0x04, "");
  sasl.begin(0xA3);
  sasl.octets(0x04, "PLAIN");
  sasl.end();
  sasl.end();
  sasl.end();
  client.send_raw(sasl.bytes());
  EXPECT_EQ(client.read()->code, code(ResultCode::auth_method_not_supported));

  lugh::ldap::ber::Writer old;
  old.begin(0x30);
  old.integer(0x02, 51);
  old.begin(0x60);
  old.integer(0x02, 2);
  old.octets(0x04, kAlice);
  old.octets(0x80, kPassword);
  old.end();
  old.end();
  client.send_raw(old.bytes());
  EXPECT_EQ(client.read()->code, code(ResultCode::protocol_error));
}

// A user disabled while bound stops at the next operation.
TEST_F(LdapConnectionTest, ABoundConnectionOutlivesNothing) {
  start();
  auto client = secure();
  ASSERT_EQ(client.bind(kAlice, kPassword)->code, 0);
  ASSERT_EQ(client.search(kBase, 0)->done.code, 0);
  ASSERT_TRUE(wait_for<Outcome<lugh::directory::User>>([&](Executor executor, auto done) {
                rig.directory->disable_user(rig.admin, alice.id, true, std::nullopt, kTestDeadline, executor, done);
              }).ok());
  EXPECT_EQ(client.search(kBase, 0)->done.code, code(ResultCode::insufficient_access_rights));
  EXPECT_EQ(client.extended(kWhoAmIOid)->value, "");
}

TEST_F(LdapConnectionTest, AMessageThatCannotBeReadEndsTheConnection) {
  start();
  auto client = secure();
  client.send_raw(std::string("\x30\x03\x02\x01\x00", 5));
  const auto notice = client.read();
  ASSERT_TRUE(notice);
  EXPECT_EQ(notice->id, 0);
  EXPECT_EQ(notice->op, ldap_client::kExtendedResponse);
  EXPECT_EQ(notice->code, code(ResultCode::protocol_error));
  EXPECT_EQ(notice->oid, "1.3.6.1.4.1.1466.20036");
  EXPECT_TRUE(client.closes());
}

// Known from the length alone, before a byte of it has arrived.
TEST_F(LdapConnectionTest, AMessageOverTheCapEndsTheConnection) {
  start();
  auto client = secure();
  client.send_raw(std::string("\x30\x84\x7F\xFF\xFF\xFF", 6));
  const auto notice = client.read();
  ASSERT_TRUE(notice);
  EXPECT_EQ(notice->code, code(ResultCode::protocol_error));
  EXPECT_TRUE(client.closes());
}

// A message may come in as many pieces as it likes, and a piece may hold many.
TEST_F(LdapConnectionTest, FramingIsTheStreams) {
  start();
  auto client = secure();
  ASSERT_EQ(client.bind(kAlice, kPassword)->code, 0);
  const auto whole = client.extended_bytes(5, kWhoAmIOid) + client.extended_bytes(6, kWhoAmIOid);
  for (std::size_t i = 0; i < whole.size(); ++i) ASSERT_TRUE(client.send_raw(whole.substr(i, 1)));
  EXPECT_EQ(client.read()->id, 5);
  EXPECT_EQ(client.read()->id, 6);
}

// More than may be pending at once: all answered, in order, by reading no faster than they go.
TEST_F(LdapConnectionTest, ThePendingCapHoldsReadsBack) {
  start(std::chrono::minutes(10), LdapServer::kMostConnections, 2);
  auto client = secure();
  ASSERT_EQ(client.bind(kAlice, kPassword)->code, 0);
  std::string many;
  for (int id = 100; id < 200; ++id) many += client.extended_bytes(id, kWhoAmIOid);
  ASSERT_TRUE(client.send_raw(many));
  for (int id = 100; id < 200; ++id) {
    const auto answer = client.read();
    ASSERT_TRUE(answer) << id;
    EXPECT_EQ(answer->id, id);
  }
}

// One TLS record arrives whole, so what is abandoned here has not begun.
TEST_F(LdapConnectionTest, Abandon) {
  start();
  auto client = secure();
  ASSERT_EQ(client.bind(kAlice, kPassword)->code, 0);
  ASSERT_TRUE(client.send_raw(client.search_bytes(10, kBase, 0) + client.search_bytes(11, kBase, 0) + client.abandon_bytes(12, 10) +
                              client.extended_bytes(13, kWhoAmIOid)));
  std::vector<std::int64_t> seen;
  for (;;) {
    const auto answer = client.read();
    ASSERT_TRUE(answer);
    seen.push_back(answer->id);
    if (answer->id == 13) break;
  }
  // 11's entry and done, and never 10's.
  EXPECT_EQ(seen, (std::vector<std::int64_t>{11, 11, 13}));
}

// What came before an unbind is answered first.
TEST_F(LdapConnectionTest, UnbindComesInItsTurn) {
  start();
  auto client = secure();
  ASSERT_EQ(client.bind(kAlice, kPassword)->code, 0);
  ASSERT_TRUE(client.send_raw(client.extended_bytes(20, kWhoAmIOid) + client.unbind_bytes(21)));
  EXPECT_EQ(client.read()->id, 20);
  EXPECT_TRUE(client.closes());
}

// RFC 4511 section 4.1.11.
TEST_F(LdapConnectionTest, ControlsItDoesNotDo) {
  start();
  auto client = secure();
  client.send_raw(client.extended_bytes(30, kWhoAmIOid, std::nullopt, "1.2.3.4"));
  const auto refused = client.read();
  ASSERT_TRUE(refused);
  EXPECT_EQ(refused->id, 30);
  EXPECT_EQ(refused->op, ldap_client::kExtendedResponse);
  EXPECT_EQ(refused->code, code(ResultCode::unavailable_critical_extension));
  // Paged results is a search's: on anything else it is a control it does not do.
  client.send_raw(client.extended_bytes(31, kWhoAmIOid, std::nullopt, kPagedResultsOid));
  EXPECT_EQ(client.read()->code, code(ResultCode::unavailable_critical_extension));
}

TEST_F(LdapConnectionTest, AnExtendedOperationItDoesNotDo) {
  start();
  auto client = secure();
  const auto answer = client.extended("1.2.3.4");
  ASSERT_TRUE(answer);
  EXPECT_EQ(answer->code, code(ResultCode::protocol_error));
  EXPECT_EQ(client.extended(kWhoAmIOid)->code, 0) << "and the connection goes on";
}

TEST_F(LdapConnectionTest, AnIdleConnectionCloses) {
  // Nothing is asserted of what happens before it closes, so a slow machine cannot change the answer.
  start(std::chrono::milliseconds(100));
  auto client = secure();
  EXPECT_TRUE(client.closes());
}

TEST_F(LdapConnectionTest, OnePastTheConnectionLimitIsClosed) {
  start(std::chrono::minutes(10), 1);
  auto first = secure();
  ASSERT_EQ(first.extended(kWhoAmIOid)->code, 0);
  // Its own listener counts its own: the first on this one is good, and the next is not.
  auto second = plaintext();
  ASSERT_EQ(second.search("", 0)->done.code, 0);
  auto third = plaintext();
  EXPECT_TRUE(third.closes());
  EXPECT_EQ(first.extended(kWhoAmIOid)->code, 0);
}

TEST_F(LdapConnectionTest, TheRateLimiter) {
  throttle = std::make_shared<lugh::http::Throttle>(rig.time, lugh::http::RateLimits{{3, 3}, {2, 2}});
  start();
  auto client = secure();
  // By address, while nobody is bound. The bind is what takes the last of it.
  EXPECT_EQ(client.extended(kWhoAmIOid)->code, 0);
  EXPECT_EQ(client.extended(kWhoAmIOid)->code, 0);
  EXPECT_EQ(client.bind(kAlice, kPassword)->code, 0);
  // By caller once bound, with a room of its own.
  EXPECT_EQ(client.extended(kWhoAmIOid)->code, 0);
  EXPECT_EQ(client.extended(kWhoAmIOid)->code, 0);
  const auto over = client.extended(kWhoAmIOid);
  ASSERT_TRUE(over);
  EXPECT_EQ(over->code, code(ResultCode::busy));
  EXPECT_EQ(client.extended(kWhoAmIOid)->code, code(ResultCode::busy));
  rig.advance(std::chrono::hours(1));
  EXPECT_EQ(client.extended(kWhoAmIOid)->code, 0);
}

TEST_F(LdapConnectionTest, StoppingClosesConnections) {
  start();
  auto client = secure();
  ASSERT_EQ(client.extended(kWhoAmIOid)->code, 0);
  ldaps->stop();
  EXPECT_TRUE(client.closes());
}

// The writes over the wire: each answered with its own response, as the bound user.
TEST_F(LdapConnectionTest, WritesOverTheWire) {
  start();
  auto client = secure();
  EXPECT_EQ(client.modify(kAlice, "cn", "Refused")->code, code(ResultCode::insufficient_access_rights)) << "bind first";
  ASSERT_EQ(client.bind(kAlice, kPassword)->code, 0);

  const auto changed = client.modify(kAlice, "cn", "Alice Smith");
  ASSERT_TRUE(changed);
  EXPECT_EQ(changed->op, 0x67);
  EXPECT_EQ(changed->code, 0) << changed->message;
  const auto read = client.search(kAlice, 0, {"cn", "lughEntryVersion"});
  ASSERT_EQ(read->entries.size(), 1u);
  EXPECT_EQ(read->entries[0].attributes.at("cn"), (std::vector<std::string>{"Alice Smith"}));

  const auto version = read->entries[0].attributes.at("lughEntryVersion").at(0);
  EXPECT_EQ(client.modify(kAlice, "cn", "Stale", ldap_client::filter_equal("lughEntryVersion", "1"))->code, code(ResultCode::assertion_failed));
  EXPECT_EQ(client.modify(kAlice, "cn", "Fresh", ldap_client::filter_equal("lughEntryVersion", version))->code, 0);
  // An assertion that cannot be read.
  EXPECT_EQ(client.modify(kAlice, "cn", "Bad", "not ber")->code, code(ResultCode::protocol_error));

  const auto added = client.add("cn=ops,ou=groups,dc=example,dc=com", {{"objectClass", {"groupOfNames"}}, {"member", {kAlice}}});
  ASSERT_TRUE(added);
  EXPECT_EQ(added->op, 0x69);
  EXPECT_EQ(added->code, 0) << added->message;
  const auto renamed = client.rename("cn=ops,ou=groups,dc=example,dc=com", "cn=operations");
  ASSERT_TRUE(renamed);
  EXPECT_EQ(renamed->op, 0x6D);
  EXPECT_EQ(renamed->code, 0) << renamed->message;
  const auto removed = client.remove("cn=operations,ou=groups,dc=example,dc=com");
  ASSERT_TRUE(removed);
  EXPECT_EQ(removed->op, 0x6B);
  EXPECT_EQ(removed->code, 0) << removed->message;
}

TEST_F(LdapConnectionTest, WritesOverPlaintextAreRefused) {
  start();
  auto client = plaintext();
  EXPECT_EQ(client.modify(kAlice, "cn", "x")->code, code(ResultCode::confidentiality_required));
}

// RFC 3062 over the wire, and a critical assertion is one it does do.
TEST_F(LdapConnectionTest, PasswordModifyOverTheWire) {
  start();
  auto client = secure();
  EXPECT_EQ(client.password_modify(kPassword, "a much better passphrase")->code, code(ResultCode::insufficient_access_rights));
  ASSERT_EQ(client.bind(kAlice, kPassword)->code, 0);
  EXPECT_EQ(client.extended(kPasswordModifyOid, std::string("not ber"))->code, code(ResultCode::protocol_error));
  const auto changed = client.password_modify(kPassword, "a much better passphrase");
  ASSERT_TRUE(changed);
  EXPECT_EQ(changed->op, ldap_client::kExtendedResponse);
  EXPECT_EQ(changed->code, 0) << changed->message;

  auto fresh = secure();
  EXPECT_EQ(fresh.bind(kAlice, kPassword)->code, code(ResultCode::invalid_credentials));
  auto again = secure();
  EXPECT_EQ(again.bind(kAlice, "a much better passphrase")->code, 0);
}

// Off by default: the plan's refusal, on either listener.
TEST_F(LdapConnectionTest, AnAnonymousBindIsRefusedByDefault) {
  start();
  auto secured = secure();
  EXPECT_EQ(secured.bind("", "")->code, code(ResultCode::inappropriate_authentication));
  auto open = plaintext();
  EXPECT_EQ(open.bind("", "")->code, code(ResultCode::confidentiality_required));
}

// What a stock client does first: on, it succeeds on either listener, and the rootDSE follows.
TEST_F(LdapConnectionTest, AnAnonymousBindWhenAllowed) {
  anonymous_bind = true;
  start();
  auto open = plaintext();
  const auto bound = open.bind("", "");
  ASSERT_TRUE(bound);
  EXPECT_EQ(bound->op, ldap_client::kBindResponse);
  EXPECT_EQ(bound->code, 0) << bound->message;
  EXPECT_EQ(open.search("", 0, {"namingContexts"})->entries.size(), 1u);
  ASSERT_TRUE(open.start_tls()) << "and it still gets to StartTLS";
  EXPECT_EQ(open.bind(kAlice, kPassword)->code, 0);

  auto secured = secure();
  EXPECT_EQ(secured.bind("", "")->code, 0);
  EXPECT_EQ(secured.search("", 0, {"namingContexts"})->entries.size(), 1u);
}

// It opens nothing: still anonymous, in every way that counts.
TEST_F(LdapConnectionTest, AnAllowedAnonymousBindOpensNothing) {
  anonymous_bind = true;
  start();
  auto client = secure();
  ASSERT_EQ(client.bind("", "")->code, 0);
  EXPECT_EQ(client.extended(kWhoAmIOid)->value, "");
  EXPECT_EQ(client.search(kBase, 0)->done.code, code(ResultCode::insufficient_access_rights));
  EXPECT_EQ(client.search(kAlice, 0)->done.code, code(ResultCode::insufficient_access_rights));
  EXPECT_EQ(client.compare(kAlice, "uid", "alice")->code, code(ResultCode::insufficient_access_rights));
  EXPECT_EQ(client.modify(kAlice, "cn", "x")->code, code(ResultCode::insufficient_access_rights));
  EXPECT_EQ(client.password_modify(kPassword, "a much better passphrase")->code, code(ResultCode::insufficient_access_rights));

  auto open = plaintext();
  ASSERT_EQ(open.bind("", "")->code, 0);
  EXPECT_EQ(open.search(kBase, 0)->done.code, code(ResultCode::confidentiality_required)) << "and plaintext carries no more";
}

// A bound connection that binds anonymously gives up who it was (RFC 4513 section 3.1.2).
TEST_F(LdapConnectionTest, AnAnonymousBindDropsTheIdentity) {
  anonymous_bind = true;
  start();
  auto client = secure();
  ASSERT_EQ(client.bind(kAlice, kPassword)->code, 0);
  ASSERT_EQ(client.search(kBase, 0)->done.code, 0);
  ASSERT_EQ(client.bind("", "")->code, 0);
  EXPECT_EQ(client.extended(kWhoAmIOid)->value, "");
  EXPECT_EQ(client.search(kBase, 0)->done.code, code(ResultCode::insufficient_access_rights));
}

// RFC 4513 section 5.1.2: the dangerous form, a name with no password, is never this.
TEST_F(LdapConnectionTest, ANameWithNoPasswordIsNeverAnonymous) {
  anonymous_bind = true;
  start();
  auto client = secure();
  EXPECT_EQ(client.bind(kAlice, "")->code, code(ResultCode::inappropriate_authentication));
  EXPECT_EQ(client.extended(kWhoAmIOid)->value, "");
  EXPECT_EQ(client.bind(" ", "")->code, code(ResultCode::inappropriate_authentication)) << "blank is not empty";
  EXPECT_EQ(client.bind("", kPassword)->code, code(ResultCode::invalid_credentials));
  auto open = plaintext();
  EXPECT_EQ(open.bind(kAlice, "")->code, code(ResultCode::confidentiality_required));
}
