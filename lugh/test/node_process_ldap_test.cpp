//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include <gtest/gtest.h>
#include <ldap.h>

#include <map>

#include "lugh/test/fixtures/ldap_client.h"
#include "lugh/test/fixtures/node_browser.h"

// LDAP on the real binary. Root signs in and enrols through the pages, as it must; root's policy
// needs a second factor, so it makes an app password through the API; and that binds and reads over
// LDAPS and over StartTLS. Unconfigured, there is no listener at all.
//
// Twice over: through Lugh's own small client, which can also send what a real client never would,
// and through OpenLDAP's libldap, the client library SSSD, PAM and most LDAP software use (the maintainer,
// 2026-11-20: "You will test with a real LDAP client"). libldap checks the server's certificate and
// name against the workspace's certificate as its CA, as a deployed client would.

using namespace node_process;
using ldap_client::Client;
namespace http = boost::beast::http;

namespace {

constexpr const char* kBase = "dc=example,dc=com";
constexpr const char* kRoot = "uid=root,ou=people,dc=example,dc=com";

// OpenLDAP's libldap, synchronous calls, one connection. Each call answers the LDAP result code.
class OpenLdap {
 public:
  // `ca` empty: the system's roots, which do not hold the workspace's certificate.
  OpenLdap(const std::string& uri, const std::filesystem::path& ca) {
    initialised = ldap_initialize(&_ld, uri.c_str());
    if (initialised != LDAP_SUCCESS) return;
    int version = LDAP_VERSION3;
    ldap_set_option(_ld, LDAP_OPT_PROTOCOL_VERSION, &version);
    timeval wait{10, 0};
    ldap_set_option(_ld, LDAP_OPT_NETWORK_TIMEOUT, &wait);
    ldap_set_option(_ld, LDAP_OPT_TIMEOUT, &wait);
    ldap_set_option(_ld, LDAP_OPT_REFERRALS, LDAP_OPT_OFF);
    int hard = LDAP_OPT_X_TLS_HARD;
    ldap_set_option(_ld, LDAP_OPT_X_TLS_REQUIRE_CERT, &hard);
    if (!ca.empty()) ldap_set_option(_ld, LDAP_OPT_X_TLS_CACERTFILE, ca.c_str());
    // A fresh client TLS context, so the settings above take effect on this handle.
    int client_context = 0;
    ldap_set_option(_ld, LDAP_OPT_X_TLS_NEWCTX, &client_context);
  }
  ~OpenLdap() {
    if (_ld) ldap_unbind_ext_s(_ld, nullptr, nullptr);
  }
  OpenLdap(const OpenLdap&) = delete;
  OpenLdap& operator=(const OpenLdap&) = delete;

  int start_tls() { return ldap_start_tls_s(_ld, nullptr, nullptr); }

  int bind(const std::string& dn, const std::string& password) {
    berval credential{password.size(), const_cast<char*>(password.data())};
    return ldap_sasl_bind_s(_ld, dn.c_str(), LDAP_SASL_SIMPLE, &credential, nullptr, nullptr, nullptr);
  }

  // RFC 4532: the authorisation identity, or "error <code>".
  std::string whoami() {
    berval* identity = nullptr;
    const int code = ldap_whoami_s(_ld, &identity, nullptr, nullptr);
    std::string out = code == LDAP_SUCCESS ? (identity ? std::string(identity->bv_val, identity->bv_len) : "") : "error " + std::to_string(code);
    if (identity) ber_bvfree(identity);
    return out;
  }

  struct Found {
    int code = -1;
    std::vector<std::string> dns;
    // Each entry's attributes, by DN.
    std::map<std::string, std::map<std::string, std::vector<std::string>>> entries;
    // RFC 2696: the cookie for the next page; empty on the last.
    std::string cookie;
  };

  // A search; with `page_size`, one page of a paged search (RFC 2696) from `cookie`.
  Found search(const std::string& base, int scope, const std::string& filter, std::vector<std::string> attributes = {}, int page_size = 0,
               const std::string& cookie = {}) {
    Found out;
    std::vector<char*> names;
    for (auto& one : attributes) names.push_back(one.data());
    names.push_back(nullptr);
    LDAPControl* page = nullptr;
    LDAPControl* controls[2] = {nullptr, nullptr};
    if (page_size > 0) {
      berval from{cookie.size(), const_cast<char*>(cookie.data())};
      if (ldap_create_page_control(_ld, static_cast<ber_int_t>(page_size), &from, 1, &page) != LDAP_SUCCESS) return out;
      controls[0] = page;
    }
    LDAPMessage* result = nullptr;
    timeval wait{10, 0};
    ldap_search_ext_s(_ld, base.c_str(), scope, filter.c_str(), attributes.empty() ? nullptr : names.data(), 0, page ? controls : nullptr, nullptr, &wait,
                      LDAP_NO_LIMIT, &result);
    if (page) ldap_control_free(page);
    if (!result) return out;
    for (auto* entry = ldap_first_entry(_ld, result); entry; entry = ldap_next_entry(_ld, entry)) {
      char* dn = ldap_get_dn(_ld, entry);
      const std::string name = dn ? dn : "";
      ldap_memfree(dn);
      out.dns.push_back(name);
      BerElement* walk = nullptr;
      for (char* attribute = ldap_first_attribute(_ld, entry, &walk); attribute; attribute = ldap_next_attribute(_ld, entry, walk)) {
        auto& values = out.entries[name][attribute];
        if (berval** found = ldap_get_values_len(_ld, entry, attribute)) {
          for (auto** value = found; *value; ++value) values.emplace_back((*value)->bv_val, (*value)->bv_len);
          ldap_value_free_len(found);
        }
        ldap_memfree(attribute);
      }
      if (walk) ber_free(walk, 0);
    }
    LDAPControl** answered = nullptr;
    ldap_parse_result(_ld, result, &out.code, nullptr, nullptr, nullptr, &answered, 0);
    if (answered) {
      if (LDAPControl* paged = ldap_control_find(LDAP_CONTROL_PAGEDRESULTS, answered, nullptr)) {
        ber_int_t estimate = 0;
        berval next{0, nullptr};
        if (ldap_parse_pageresponse_control(_ld, paged, &estimate, &next) == LDAP_SUCCESS && next.bv_val) {
          out.cookie.assign(next.bv_val, next.bv_len);
          ldap_memfree(next.bv_val);
        }
      }
      ldap_controls_free(answered);
    }
    ldap_msgfree(result);
    return out;
  }

  int compare(const std::string& dn, const std::string& attribute, const std::string& value) {
    berval asserted{value.size(), const_cast<char*>(value.data())};
    return ldap_compare_ext_s(_ld, dn.c_str(), attribute.c_str(), &asserted, nullptr, nullptr);
  }

  int add(const std::string& dn, const std::map<std::string, std::vector<std::string>>& attributes) {
    std::vector<std::vector<char*>> values;
    std::vector<LDAPMod> mods(attributes.size());
    std::vector<LDAPMod*> list;
    std::size_t i = 0;
    values.reserve(attributes.size());
    for (const auto& [name, held] : attributes) {
      auto& strings = values.emplace_back();
      for (const auto& one : held) strings.push_back(const_cast<char*>(one.c_str()));
      strings.push_back(nullptr);
      mods[i].mod_op = LDAP_MOD_ADD;
      mods[i].mod_type = const_cast<char*>(name.c_str());
      mods[i].mod_vals.modv_strvals = strings.data();
      list.push_back(&mods[i]);
      ++i;
    }
    list.push_back(nullptr);
    return ldap_add_ext_s(_ld, dn.c_str(), list.data(), nullptr, nullptr);
  }

  int replace(const std::string& dn, const std::string& attribute, const std::string& value) {
    char* strings[2] = {const_cast<char*>(value.c_str()), nullptr};
    LDAPMod mod{};
    mod.mod_op = LDAP_MOD_REPLACE;
    mod.mod_type = const_cast<char*>(attribute.c_str());
    mod.mod_vals.modv_strvals = strings;
    LDAPMod* list[2] = {&mod, nullptr};
    return ldap_modify_ext_s(_ld, dn.c_str(), list, nullptr, nullptr);
  }

  int remove(const std::string& dn) { return ldap_delete_ext_s(_ld, dn.c_str(), nullptr, nullptr); }

  // RFC 3062, the bound identity's own password.
  int change_password(const std::string& old_password, const std::string& new_password) {
    berval before{old_password.size(), const_cast<char*>(old_password.data())};
    berval after{new_password.size(), const_cast<char*>(new_password.data())};
    berval generated{0, nullptr};
    const int code = ldap_passwd_s(_ld, nullptr, &before, &after, &generated, nullptr, nullptr);
    if (generated.bv_val) ldap_memfree(generated.bv_val);
    return code;
  }

  // What libldap last said beside a result code: a TLS failure's reason, the server's message.
  std::string diagnostic() {
    char* text = nullptr;
    ldap_get_option(_ld, LDAP_OPT_DIAGNOSTIC_MESSAGE, &text);
    std::string out = text ? text : "";
    if (text) ldap_memfree(text);
    return out;
  }

  int initialised = -1;

 private:
  LDAP* _ld = nullptr;
};

// By address: libldap checks "localhost" against the machine's own hostname instead (OpenLDAP's
// tls_o.c), so a name of localhost never matches a certificate for localhost.
std::string ldaps_uri(std::uint16_t port) { return "ldaps://127.0.0.1:" + std::to_string(port); }
std::string ldap_uri(std::uint16_t port) { return "ldap://127.0.0.1:" + std::to_string(port); }

class NodeProcessLdap : public ::testing::Test {
 protected:
  void SetUp() override {
    ASSERT_EQ(node.made.status, 0) << node.made.err;
    password = root_password(node.made.err);
    ASSERT_FALSE(password.empty()) << node.made.err;
    ldaps_port = dannan::test::free_port();
    plain_port = dannan::test::free_port();
    const auto config = workspace.path("config.yaml");
    // An issuer, so root's first sign-in can enrol a passkey and administer at phr.
    write_file(config, "ldap: { port: " + std::to_string(ldaps_port) + ", starttls_port: " + std::to_string(plain_port) + ", base_dn: '" + kBase +
                           "' }\noauth: { issuer: " + RootBrowser::kTestIssuer + " }\n");
    serving.emplace(workspace, node.state, node.credentials, std::nullopt, std::vector<std::string>{"--config", config.string()});
    ASSERT_TRUE(serving->up()) << serving->log();
    root.port = serving->port();
    root.sign_in_and_enrol_passkey(password);
    ASSERT_FALSE(HasFatalFailure());

    const auto made = root.api(http::verb::post, "/api/v1/me/app-passwords", R"({"name":"the test","scopes":["lugh:directory.read"]})");
    ASSERT_TRUE(made);
    ASSERT_EQ(made->status, 201u) << made->body;
    app_password = std::string(boost::json::parse(made->body).at("password").as_string());
  }

  void reads_as_root(Client& client) {
    const auto bound = client.bind(kRoot, app_password);
    ASSERT_TRUE(bound);
    ASSERT_EQ(bound->code, 0) << bound->message;
    EXPECT_EQ(client.extended(lugh::ldap::kWhoAmIOid)->value, std::string("dn:") + kRoot);

    const auto found = client.search(kBase, 2, {"memberOf"}, ldap_client::filter_equal("uid", "root"));
    ASSERT_TRUE(found);
    EXPECT_EQ(found->done.code, 0) << found->done.message;
    ASSERT_EQ(found->entries.size(), 1u);
    EXPECT_EQ(found->entries[0].dn, kRoot);
    // Genesis puts root in the administrators, which is where its scopes come from.
    EXPECT_FALSE(found->entries[0].attributes.at("memberOf").empty());
    EXPECT_EQ(client.compare(kRoot, "uid", "root")->code, static_cast<int>(lugh::ldap::ResultCode::compare_true));
  }

  Workspace workspace;
  Initialised node{workspace};
  std::optional<Serving> serving;
  RootBrowser root;
  std::string password;
  std::string app_password;
  std::uint16_t ldaps_port = 0;
  std::uint16_t plain_port = 0;
};

}  // namespace

TEST_F(NodeProcessLdap, OverLdaps) {
  Client client(ldaps_port, Client::Mode::ldaps);
  ASSERT_TRUE(client.connected);
  reads_as_root(client);
}

TEST_F(NodeProcessLdap, OverStartTls) {
  Client client(plain_port, Client::Mode::plaintext);
  ASSERT_TRUE(client.connected);
  // The rootDSE before anything, which is how a client learns StartTLS is there.
  const auto root_dse = client.search("", 0, {"supportedExtension"});
  ASSERT_TRUE(root_dse);
  ASSERT_EQ(root_dse->entries.size(), 1u);
  const auto& extensions = root_dse->entries[0].attributes.at("supportedExtension");
  EXPECT_NE(std::find(extensions.begin(), extensions.end(), lugh::ldap::kStartTlsOid), extensions.end());
  EXPECT_EQ(client.bind(kRoot, app_password)->code, static_cast<int>(lugh::ldap::ResultCode::confidentiality_required));

  ASSERT_TRUE(client.start_tls());
  reads_as_root(client);
}

// Root's policy asks for a second factor, which a bind cannot carry.
TEST_F(NodeProcessLdap, RootsMainPasswordIsRefused) {
  Client client(ldaps_port, Client::Mode::ldaps);
  const auto bound = client.bind(kRoot, password);
  ASSERT_TRUE(bound);
  EXPECT_EQ(bound->code, static_cast<int>(lugh::ldap::ResultCode::invalid_credentials));

  const auto text = serving->stop();
  EXPECT_EQ(text.find(password), std::string::npos) << "root's password is never logged";
  EXPECT_EQ(text.find(app_password), std::string::npos) << "nor an app password";
}

// A revoked app password stops a connection already bound with it.
TEST_F(NodeProcessLdap, RevokingStopsAConnectionAlreadyBound) {
  Client client(ldaps_port, Client::Mode::ldaps);
  reads_as_root(client);
  ASSERT_FALSE(HasFatalFailure());
  const auto listed = root.browser(http::verb::get, "/api/v1/me/app-passwords");
  ASSERT_TRUE(listed);
  const auto parsed = boost::json::parse(listed->body);
  const auto id = std::string(parsed.at("app_passwords").as_array().at(0).at("id").as_string());
  const auto revoked = root.api(http::verb::delete_, "/api/v1/me/app-passwords/" + id, "");
  ASSERT_TRUE(revoked);
  ASSERT_EQ(revoked->status, 204u) << revoked->body;
  EXPECT_EQ(client.extended(lugh::ldap::kWhoAmIOid)->value, "");
  EXPECT_EQ(client.bind(kRoot, app_password)->code, static_cast<int>(lugh::ldap::ResultCode::invalid_credentials));
}

// A provisioning tool: an app password that carries directory.write, its changes under its owner.
TEST_F(NodeProcessLdap, WritesThroughAnAppPasswordThatMay) {
  const auto made =
      root.api(http::verb::post, "/api/v1/me/app-passwords", R"({"name":"provisioning","scopes":["lugh:directory.read","lugh:directory.write"]})");
  ASSERT_TRUE(made);
  ASSERT_EQ(made->status, 201u) << made->body;
  const auto writing = std::string(boost::json::parse(made->body).at("password").as_string());

  Client client(ldaps_port, Client::Mode::ldaps);
  ASSERT_EQ(client.bind(kRoot, writing)->code, 0);
  const std::string entry = std::string("uid=dana,ou=people,") + kBase;
  const auto added = client.add(entry, {{"objectClass", {"inetOrgPerson"}}, {"cn", {"Dana"}}, {"sn", {"Dana"}}, {"mail", {"dana@example.com"}}});
  ASSERT_TRUE(added);
  ASSERT_EQ(added->code, 0) << added->message;
  EXPECT_EQ(client.modify(entry, "givenName", "Dana")->code, 0);

  // The API sees what LDAP wrote: one directory, two front ends.
  const auto listed = root.browser(http::verb::get, "/api/v1/users");
  ASSERT_TRUE(listed);
  EXPECT_NE(listed->body.find("dana@example.com"), std::string::npos);

  EXPECT_EQ(client.remove(entry)->code, 0);
  EXPECT_EQ(root.browser(http::verb::get, "/api/v1/users")->body.find("dana@example.com"), std::string::npos);

  // The read-only one may not.
  Client reader(ldaps_port, Client::Mode::ldaps);
  ASSERT_EQ(reader.bind(kRoot, app_password)->code, 0);
  EXPECT_EQ(reader.modify(kRoot, "cn", "x")->code, static_cast<int>(lugh::ldap::ResultCode::insufficient_access_rights));
  // And no app password changes the main one.
  EXPECT_EQ(client.password_modify(password, "a much better passphrase")->code, static_cast<int>(lugh::ldap::ResultCode::unwilling_to_perform));
}

// Root was made before anything could number it: the backfill does, and LDAP shows it.
TEST(NodeProcessLdapPosix, TheBackfillOnTheRealBinary) {
  Workspace workspace;
  const Initialised node(workspace);
  ASSERT_EQ(node.made.status, 0) << node.made.err;
  const auto ldaps_port = dannan::test::free_port();
  const auto config = workspace.path("config.yaml");
  write_file(config, "ldap: { port: " + std::to_string(ldaps_port) + ", base_dn: '" + kBase +
                         "', posix: { uid_range: 10000-19999, gid_range: 20000-29999, primary_group: administrators, shell: /bin/zsh } }\n" +
                         "oauth: { issuer: " + RootBrowser::kTestIssuer + " }\n");
  Serving serving(workspace, node.state, node.credentials, std::nullopt, {"--config", config.string()});
  ASSERT_TRUE(serving.up()) << serving.log();
  RootBrowser root(serving.port());
  // At phr: numbering the directory is administering.
  root.sign_in_and_enrol_passkey(root_password(node.made.err));
  ASSERT_FALSE(HasFatalFailure());

  const auto made = root.api(http::verb::post, "/api/v1/me/app-passwords", R"({"name":"the test"})");
  ASSERT_TRUE(made);
  ASSERT_EQ(made->status, 201u) << made->body;
  Client client(ldaps_port, Client::Mode::ldaps);
  ASSERT_EQ(client.bind(kRoot, std::string(boost::json::parse(made->body).at("password").as_string()))->code, 0);

  const auto before = client.search(kRoot, 0);
  ASSERT_EQ(before->entries.size(), 1u);
  EXPECT_EQ(before->entries[0].attributes.count("uidNumber"), 0u);

  const auto allocated = root.api(http::verb::post, "/api/v1/ldap/posix/allocate", "{}");
  ASSERT_TRUE(allocated);
  ASSERT_EQ(allocated->status, 200u) << allocated->body;
  EXPECT_EQ(boost::json::parse(allocated->body).at("users"), 1);

  const auto after = client.search(kRoot, 0);
  ASSERT_EQ(after->entries.size(), 1u);
  EXPECT_EQ(after->entries[0].attributes.at("uidNumber"), (std::vector<std::string>{"10000"}));
  EXPECT_EQ(after->entries[0].attributes.at("gidNumber").size(), 1u);
  EXPECT_EQ(after->entries[0].attributes.at("loginShell"), (std::vector<std::string>{"/bin/zsh"}));
}

// The setting reaches the listeners on the real binary.
TEST(NodeProcessLdapAnonymous, TheSetting) {
  const auto with = [](const std::string& setting, int expected) {
    Workspace workspace;
    const Initialised node(workspace);
    ASSERT_EQ(node.made.status, 0) << node.made.err;
    const auto plain_port = dannan::test::free_port();
    const auto config = workspace.path("config.yaml");
    write_file(config, "ldap: { starttls_port: " + std::to_string(plain_port) + ", base_dn: '" + kBase + "'" + setting + " }\n");
    Serving serving(workspace, node.state, node.credentials, std::nullopt, {"--config", config.string()});
    ASSERT_TRUE(serving.up()) << serving.log();
    Client client(plain_port, Client::Mode::plaintext);
    const auto bound = client.bind("", "");
    ASSERT_TRUE(bound);
    EXPECT_EQ(bound->code, expected) << setting;
  };
  with("", static_cast<int>(lugh::ldap::ResultCode::confidentiality_required));
  with(", anonymous_bind: false", static_cast<int>(lugh::ldap::ResultCode::confidentiality_required));
  with(", anonymous_bind: true", 0);
}

TEST(NodeProcessLdapOff, UnconfiguredThereIsNoListener) {
  Workspace workspace;
  const Initialised node(workspace);
  ASSERT_EQ(node.made.status, 0) << node.made.err;
  Serving serving(workspace, node.state, node.credentials);
  ASSERT_TRUE(serving.up()) << serving.log();
  EXPECT_EQ(serving.log().find("LDAP listening"), std::string::npos);
  // Nor is the backfill served without a range.
  EXPECT_EQ(send(serving.port(), http::verb::post, "/api/v1/ldap/posix/allocate")->status, 404u);
}

// OpenLDAP's libldap, as deployed software meets Lugh: LDAPS, the server's certificate and name
// checked (RFC 4513 section 3.1.3, here an address in subjectAltName), a simple bind with an app password, Who am I? (RFC 4532), a
// search, a compare (RFC 4511 section 4.10).
TEST_F(NodeProcessLdap, ARealClientBindsAndReadsOverLdaps) {
  OpenLdap client(ldaps_uri(ldaps_port), workspace.certificate);
  ASSERT_EQ(client.initialised, LDAP_SUCCESS);
  ASSERT_EQ(client.bind(kRoot, app_password), LDAP_SUCCESS) << client.diagnostic();
  EXPECT_EQ(client.whoami(), std::string("dn:") + kRoot);

  const auto found = client.search(kBase, LDAP_SCOPE_SUBTREE, "(uid=root)", {"uid", "memberOf"});
  EXPECT_EQ(found.code, LDAP_SUCCESS);
  ASSERT_EQ(found.dns, std::vector<std::string>{kRoot});
  EXPECT_EQ(found.entries.at(kRoot).at("uid"), std::vector<std::string>{"root"});
  EXPECT_FALSE(found.entries.at(kRoot).at("memberOf").empty());
  EXPECT_EQ(client.compare(kRoot, "uid", "root"), LDAP_COMPARE_TRUE);
  EXPECT_EQ(client.compare(kRoot, "uid", "someone"), LDAP_COMPARE_FALSE);
}

// RFC 4511 section 4.14 and RFC 4513 section 3: a plaintext connection learns StartTLS from the
// rootDSE, is refused a bind before it, and upgrades in place.
TEST_F(NodeProcessLdap, ARealClientUpgradesWithStartTls) {
  OpenLdap client(ldap_uri(plain_port), workspace.certificate);
  ASSERT_EQ(client.initialised, LDAP_SUCCESS);
  const auto root_dse = client.search("", LDAP_SCOPE_BASE, "(objectClass=*)", {"supportedExtension"});
  ASSERT_EQ(root_dse.code, LDAP_SUCCESS);
  ASSERT_EQ(root_dse.dns.size(), 1u);
  const auto& extensions = root_dse.entries.at("").at("supportedExtension");
  EXPECT_NE(std::find(extensions.begin(), extensions.end(), LDAP_EXOP_START_TLS), extensions.end());
  EXPECT_EQ(client.bind(kRoot, app_password), LDAP_CONFIDENTIALITY_REQUIRED);

  ASSERT_EQ(client.start_tls(), LDAP_SUCCESS) << client.diagnostic();
  ASSERT_EQ(client.bind(kRoot, app_password), LDAP_SUCCESS);
  EXPECT_EQ(client.whoami(), std::string("dn:") + kRoot);
}

// A client that does not trust the server's certificate never gets as far as a bind.
TEST_F(NodeProcessLdap, ARealClientRefusesAServerItCannotVerify) {
  OpenLdap client(ldaps_uri(ldaps_port), {});
  ASSERT_EQ(client.initialised, LDAP_SUCCESS);
  // A client-side failure (libldap's codes are negative), never a server's answer.
  EXPECT_LT(client.bind(kRoot, app_password), 0);
}

TEST_F(NodeProcessLdap, ARealClientIsRefusedAWrongPassword) {
  OpenLdap client(ldaps_uri(ldaps_port), workspace.certificate);
  EXPECT_EQ(client.bind(kRoot, "not the password"), LDAP_INVALID_CREDENTIALS);
  EXPECT_EQ(client.bind("uid=nobody,ou=people,dc=example,dc=com", app_password), LDAP_INVALID_CREDENTIALS);
  // Root's main password needs a second factor a bind cannot carry.
  EXPECT_EQ(client.bind(kRoot, password), LDAP_INVALID_CREDENTIALS);
}

// RFC 2696: a paged search walks the same entries a whole one finds, a page at a time, the last
// page's cookie empty.
TEST_F(NodeProcessLdap, ARealClientPagesASearch) {
  OpenLdap client(ldaps_uri(ldaps_port), workspace.certificate);
  ASSERT_EQ(client.bind(kRoot, app_password), LDAP_SUCCESS);
  const auto whole = client.search(kBase, LDAP_SCOPE_SUBTREE, "(objectClass=*)", {"1.1"});
  ASSERT_EQ(whole.code, LDAP_SUCCESS);
  ASSERT_GE(whole.dns.size(), 3u);

  std::vector<std::string> paged;
  std::string cookie;
  int pages = 0;
  do {
    const auto page = client.search(kBase, LDAP_SCOPE_SUBTREE, "(objectClass=*)", {"1.1"}, 2, cookie);
    ASSERT_EQ(page.code, LDAP_SUCCESS);
    EXPECT_LE(page.dns.size(), 2u);
    paged.insert(paged.end(), page.dns.begin(), page.dns.end());
    cookie = page.cookie;
    ASSERT_LT(++pages, 100) << "the cookie never emptied";
  } while (!cookie.empty());
  EXPECT_GE(pages, 2);
  auto expected = whole.dns;
  std::sort(expected.begin(), expected.end());
  std::sort(paged.begin(), paged.end());
  EXPECT_EQ(paged, expected);
}

// A provisioning tool through libldap: add, modify and delete under an app password that carries
// directory.write; the API sees each; a read-only one is refused; no app password changes the main
// password (RFC 3062).
TEST_F(NodeProcessLdap, ARealClientWritesThroughAnAppPasswordThatMay) {
  const auto made =
      root.api(http::verb::post, "/api/v1/me/app-passwords", R"({"name":"provisioning","scopes":["lugh:directory.read","lugh:directory.write"]})");
  ASSERT_TRUE(made);
  ASSERT_EQ(made->status, 201u) << made->body;
  const auto writing = std::string(boost::json::parse(made->body).at("password").as_string());

  OpenLdap client(ldaps_uri(ldaps_port), workspace.certificate);
  ASSERT_EQ(client.bind(kRoot, writing), LDAP_SUCCESS);
  const std::string entry = std::string("uid=erin,ou=people,") + kBase;
  ASSERT_EQ(client.add(entry, {{"objectClass", {"inetOrgPerson"}}, {"uid", {"erin"}}, {"cn", {"Erin"}}, {"sn", {"Erin"}}, {"mail", {"erin@example.com"}}}),
            LDAP_SUCCESS);
  EXPECT_NE(root.browser(http::verb::get, "/api/v1/users")->body.find("erin@example.com"), std::string::npos);
  EXPECT_EQ(client.replace(entry, "givenName", "Erin"), LDAP_SUCCESS);
  const auto read = client.search(entry, LDAP_SCOPE_BASE, "(objectClass=*)", {"givenName"});
  ASSERT_EQ(read.dns.size(), 1u);
  EXPECT_EQ(read.entries.at(entry).at("givenName"), std::vector<std::string>{"Erin"});
  EXPECT_EQ(client.remove(entry), LDAP_SUCCESS);
  EXPECT_EQ(root.browser(http::verb::get, "/api/v1/users")->body.find("erin@example.com"), std::string::npos);
  EXPECT_EQ(client.change_password(password, "a much better passphrase"), LDAP_UNWILLING_TO_PERFORM);

  OpenLdap reader(ldaps_uri(ldaps_port), workspace.certificate);
  ASSERT_EQ(reader.bind(kRoot, app_password), LDAP_SUCCESS);
  EXPECT_EQ(reader.replace(kRoot, "cn", "x"), LDAP_INSUFFICIENT_ACCESS);
}
