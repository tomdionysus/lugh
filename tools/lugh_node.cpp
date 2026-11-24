//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The composition root: the one file that names every concrete class. lugh-node is a Dannan node,
// and its main is Dannan's node-program helper (dannan/supervise/node_program.h): the settings, the
// node, the signals and the drain are the helper's. Lugh builds the adapters and the pools they block
// on, opens the keyring and the store in a coroutine on the node's io_context, and starts its
// listeners; the helper drains and stops it, in reverse. `lugh-node init` is genesis: the keyring,
// the store, and root.

#include <unistd.h>

#include <atomic>
#include <boost/asio.hpp>
#include <cerrno>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "dannan/identity/cluster_key.h"
#include "dannan/identity/crypto.h"
#include "dannan/identity/secure_memory.h"
#include "dannan/status/log.h"
#include "dannan/supervise/node_program.h"
#include "lugh/api/app_password_routes.h"
#include "lugh/api/app_routes.h"
#include "lugh/api/audit_routes.h"
#include "lugh/api/factor_routes.h"
#include "lugh/api/group_routes.h"
#include "lugh/api/key_routes.h"
#include "lugh/api/ldap_routes.h"
#include "lugh/api/me_routes.h"
#include "lugh/api/policy_routes.h"
#include "lugh/api/scope_routes.h"
#include "lugh/api/session_routes.h"
#include "lugh/api/user_routes.h"
#include "lugh/apps/apps.h"
#include "lugh/audit/audit_log.h"
#include "lugh/authn/authenticator.h"
#include "lugh/authn/challenges.h"
#include "lugh/authn/genesis.h"
#include "lugh/client/https.h"
#include "lugh/core/awaited.h"
#include "lugh/directory/directory.h"
#include "lugh/directory/posix_numbers.h"
#include "lugh/http/client_address.h"
#include "lugh/http/health_routes.h"
#include "lugh/http/http_server.h"
#include "lugh/http/outbound.h"
#include "lugh/http/rate_limiter.h"
#include "lugh/http/router.h"
#include "lugh/http/static_site.h"
#include "lugh/keys/keyring_manager.h"
#include "lugh/ldap/ldap_server.h"
#include "lugh/ldap/operations.h"
#include "lugh/node/config.h"
#include "lugh/oauth/backchannel.h"
#include "lugh/oauth/client_auth.h"
#include "lugh/oauth/consents.h"
#include "lugh/oauth/device_grants.h"
#include "lugh/oauth/dpop.h"
#include "lugh/oauth/flow_routes.h"
#include "lugh/oauth/issuer.h"
#include "lugh/oauth/logout_routes.h"
#include "lugh/oauth/metadata_routes.h"
#include "lugh/oauth/refresh_tokens.h"
#include "lugh/scopes/grants.h"
#include "lugh/session/pre_sessions.h"
#include "lugh/session/reauthentications.h"
#include "lugh/session/session_callers.h"
#include "lugh/session/sessions.h"
#include "lugh/signin/pages.h"
#include "lugh/store/sealed_store.h"
#include "lugh/store/tables.h"
#include "lugh/system/system_console.h"
#include "lugh/system/system_files.h"
#include "lugh/tokens/signing_keys.h"
#include "lugh/version.h"

namespace {

using namespace lugh;

// The two pools the rest of Lugh suspends on. Blocking: a file's system calls, and a
// person at the console, neither of which has readiness to wait on. Hashing: Argon2id, 64
// MiB each, so its size is what bounds the memory sign-ins can take at once (the unit's
// MemoryMax is 256M).
constexpr std::size_t kBlockingThreads = 2;
constexpr std::size_t kHashingThreads = 2;

// Runs a coroutine on the io_context until it is done, before anything is served.
template <typename T>
T run_until(boost::asio::io_context& io, Task<T> task) {
  auto future = boost::asio::co_spawn(io, std::move(task), boost::asio::use_future);
  io.run();
  io.restart();
  return future.get();
}

// Key material is on Dannan's locked pages when the lock limit allows. Said once the keys
// are in hand, when it is known whether it did.
void warn_if_unlocked(const dannan::status::ScopedLogger& logger) {
  if (const auto unlocked = dannan::identity::unlocked_secure_allocations(); unlocked > 0) {
    logger.warn(std::to_string(unlocked) + " allocations of key material could not be locked into memory (RLIMIT_MEMLOCK) and may be swapped out");
  }
}

bool write_all(int fd, const SecureBuffer& data) {
  std::size_t done = 0;
  while (done < data.size()) {
    const auto put = ::write(fd, data.data() + done, data.size() - done);
    if (put < 0 && errno == EINTR) continue;
    if (put <= 0) return false;
    done += static_cast<std::size_t>(put);
  }
  return true;
}

// Every table, with the indexes of those that have any.
std::vector<store::TableSpec> all_tables() {
  std::vector<store::TableSpec> tables;
  auto indexed = directory::table_specs();
  indexed.push_back(apps::table_spec());
  for (const auto name : store::kTables) {
    store::TableSpec spec{std::string(name), {}};
    for (const auto& one : indexed) {
      if (one.name == name) spec = one;
    }
    tables.push_back(std::move(spec));
  }
  return tables;
}

struct Ports {
  // The node's one sink; each component scopes its own logger over it.
  std::shared_ptr<dannan::status::LogSink> log;
  const dannan::contract::TimeSource& time;
  const dannan::contract::WallClock& wall;
  std::shared_ptr<system::Files> files;
  std::shared_ptr<system::Console> console;
  std::shared_ptr<keys::KeyringManager> keyrings;
  Executor blocking;
  Executor hashing;
};

// Everything that is up once the store is open, for the routes.
struct Services {
  std::shared_ptr<store::SealedStore> store;
  std::shared_ptr<audit::AuditLog> audit;
  std::shared_ptr<directory::Directory> directory;
  std::shared_ptr<authn::Factors> factors;
  std::shared_ptr<authn::Policies> policies;
  std::shared_ptr<authn::EnrolmentLinks> links;
  std::shared_ptr<authn::Authenticator> authenticator;
  std::shared_ptr<apps::Apps> apps;
  std::shared_ptr<scopes::Grants> grants;
  std::shared_ptr<tokens::SigningKeys> keys;
  std::shared_ptr<session::Sessions> sessions;
  std::shared_ptr<authn::AppPasswords> app_passwords;
  std::shared_ptr<oauth::Consents> consents;
  std::shared_ptr<authn::Passwords> passwords;
};

// The cluster's birth, once its first keyring is saved: the store under it, then root,
// whose password is shown once and is the only credential there will ever have been.
Task<int> genesis(Ports ports, keys::Keyring keyring, std::string state_directory) {
  const dannan::status::ScopedLogger logger(ports.log, "node");
  const auto failed = [&](const std::string& why) {
    logger.error(why + "; nothing is protected yet: remove " + state_directory + " and run init again");
    return 1;
  };

  const auto opened = co_await store::SealedStore::open(ports.log, ports.files, ports.keyrings, std::move(keyring), state_directory + "/store", all_tables());
  if (!opened.ok) co_return failed(opened.error);
  const auto audit = co_await awaited<Result<std::shared_ptr<audit::AuditLog>>>([&](Executor executor, Done<Result<std::shared_ptr<audit::AuditLog>>> done) {
    audit::AuditLog::open(ports.log, opened.value, ports.wall, kTransitionDeadline, std::move(executor), std::move(done));
  });
  if (!audit.ok) co_return failed(audit.error);

  auto directory = std::make_shared<directory::Directory>(ports.log, opened.value, ports.wall, audit.value);
  auto passwords = std::make_shared<authn::Passwords>(ports.log, opened.value, ports.wall, audit.value, ports.hashing, crypto::Argon2Costs{},
                                                      authn::PasswordRules{}, authn::BreachedPasswords{});
  auto links = std::make_shared<authn::EnrolmentLinks>(opened.value, ports.wall, directory, audit.value);
  auto applications = std::make_shared<apps::Apps>(opened.value, ports.wall, directory, audit.value, ports.hashing, apps::Apps::Settings{});
  auto grants = std::make_shared<scopes::Grants>(opened.value, directory, applications, audit.value);
  const auto password = co_await awaited<Outcome<Secret>>([&](Executor executor, Done<Outcome<Secret>> done) {
    authn::Genesis(directory, passwords, links, grants, audit.value).run(kTransitionDeadline, std::move(executor), std::move(done));
  });
  if (!password.ok()) co_return failed(password.message);

  logger.info("Genesis: root, in administrators");
  ports.console->show_secret("The root password, shown this once and kept nowhere. Sign in as root with it, and enrol a second factor:", password.value);
  co_return 0;
}

// `lugh-node init`. With a credential, the master key goes to standard output, for
// systemd-creds to encrypt, and only once it has gone is the keyring saved.
Task<int> run_init(bool passphrase, Ports ports, std::string state_directory) {
  auto& keyrings = *ports.keyrings;
  const dannan::status::ScopedLogger logger(ports.log, "node");
  if (passphrase) {
    auto made = co_await keyrings.create_with_passphrase(crypto::Argon2Costs{});
    if (!made.ok) {
      logger.error(made.error);
      co_return 1;
    }
    logger.info("Every start will ask for the passphrase");
    warn_if_unlocked(logger);
    co_return co_await genesis(ports, std::move(made.value), state_directory);
  }

  if (::isatty(STDOUT_FILENO) == 1) {
    logger.error("init writes the master key to standard output, which is a terminal; pipe it to systemd-creds encrypt (see lugh --help)");
    co_return 1;
  }

  auto made = co_await keyrings.create_for_credential();
  if (!made.ok) {
    logger.error(made.error);
    co_return 1;
  }

  // A pipe can be slow to drain; it is written on the blocking pool.
  if (!co_await offload(ports.blocking, [&key = made.value.master_key] { return write_all(STDOUT_FILENO, key); })) {
    logger.error("cannot write the master key to standard output; no keyring was saved");
    co_return 1;
  }

  if (const auto saved = co_await keyrings.save_new(made.value.keyring); !saved.ok) {
    logger.error(saved.error);
    co_return 1;
  }

  logger.info(std::string("The master key went to standard output. Load it as the credential ") + keys::kCredentialName +
              "; nothing under this keyring can be opened without it");
  warn_if_unlocked(logger);
  co_return co_await genesis(ports, std::move(made.value.keyring), state_directory);
}

// The keyring, then the store under it, then the services over it, before the service says
// it is up: a node that cannot read its tables whole does not serve.
Task<Result<Services>> lugh_start(Ports ports, Config config) {
  using Answer = Result<Services>;
  const dannan::status::ScopedLogger logger(ports.log, "node");

  auto keyring = co_await ports.keyrings->open();
  if (!keyring.ok) co_return Answer::failure(keyring.error);

  auto opened =
      co_await store::SealedStore::open(ports.log, ports.files, ports.keyrings, std::move(keyring.value), config.state_directory + "/store", all_tables());
  if (!opened.ok) co_return Answer::failure(opened.error);
  warn_if_unlocked(logger);

  Services services;
  services.store = opened.value;
  auto audit = co_await awaited<Result<std::shared_ptr<audit::AuditLog>>>([&](Executor executor, Done<Result<std::shared_ptr<audit::AuditLog>>> done) {
    audit::AuditLog::open(ports.log, services.store, ports.wall, kTransitionDeadline, std::move(executor), std::move(done));
  });
  if (!audit.ok) co_return Answer::failure(audit.error);
  services.audit = audit.value;

  authn::BreachedPasswords breached;
  if (!config.breached_passwords.empty()) {
    auto loaded = co_await authn::BreachedPasswords::load(*ports.files, config.breached_passwords);
    if (!loaded.ok) co_return Answer::failure(loaded.error);
    breached = std::move(loaded.value);
    logger.info(std::to_string(breached.size()) + " breached passwords refused");
  }

  const auto& store = services.store;
  services.directory = std::make_shared<directory::Directory>(ports.log, store, ports.wall, services.audit);
  auto passwords = std::make_shared<authn::Passwords>(ports.log, store, ports.wall, services.audit, ports.hashing, crypto::Argon2Costs{},
                                                      authn::PasswordRules{}, std::move(breached));
  services.factors = std::make_shared<authn::Factors>(ports.log, store, ports.wall, services.audit, ports.hashing);
  services.directory->dependent_add(passwords);
  services.directory->dependent_add(services.factors);
  services.app_passwords = std::make_shared<authn::AppPasswords>(store, ports.wall, services.directory, services.audit, ports.hashing);
  services.directory->dependent_add(services.app_passwords);
  services.consents = std::make_shared<oauth::Consents>(store, services.audit);
  services.policies = std::make_shared<authn::Policies>(store, services.directory, services.audit);
  services.links = std::make_shared<authn::EnrolmentLinks>(store, ports.wall, services.directory, services.audit);
  services.passwords = passwords;
  apps::Apps::Settings app_settings;
  app_settings.allow_client_secrets = config.allow_client_secrets;
  services.apps = std::make_shared<apps::Apps>(store, ports.wall, services.directory, services.audit, ports.hashing, app_settings);
  services.grants = std::make_shared<scopes::Grants>(store, services.directory, services.apps, services.audit);
  services.keys = std::make_shared<tokens::SigningKeys>(store, ports.wall, services.audit, tokens::SigningKeys::Settings{});
  const auto keys_open =
      co_await awaited<Status>([&](Executor executor, Done<Status> done) { services.keys->open(kTransitionDeadline, std::move(executor), std::move(done)); });
  if (!keys_open.ok) co_return Answer::failure(keys_open.error);
  services.sessions =
      std::make_shared<session::Sessions>(store, ports.wall, services.directory, services.grants, services.audit, session::Sessions::Settings{});
  const auto sessions_open = co_await awaited<Status>(
      [&](Executor executor, Done<Status> done) { services.sessions->open(kTransitionDeadline, std::move(executor), std::move(done)); });
  if (!sessions_open.ok) co_return Answer::failure(sessions_open.error);
  // Reached by the API now, and by the sign-in routes from P6.
  services.authenticator = std::make_shared<authn::Authenticator>(ports.log, ports.time, services.directory, passwords, services.factors, services.policies,
                                                                  services.links, services.audit, authn::Authenticator::Settings{});

  logger.info(std::to_string((co_await awaited_value<std::vector<directory::User>>([&](Executor executor, Done<Outcome<std::vector<directory::User>>> done) {
                               services.directory->users(kTransitionDeadline, std::move(executor), std::move(done));
                             })).size()) +
              " users, " +
              std::to_string((co_await awaited_value<std::vector<directory::Group>>([&](Executor executor, Done<Outcome<std::vector<directory::Group>>> done) {
                               services.directory->groups(kTransitionDeadline, std::move(executor), std::move(done));
                             })).size()) +
              " groups, " + std::to_string(services.audit->size()) + " audit entries");
  co_return Answer::success(std::move(services));
}

// A cluster of one, when the operator names no cluster: no cluster.key and no cluster.bootstrap.
// Its key is the node's own, made at the first start in the state directory (0600); the node listens
// on loopback, on a port of its own choosing, since there is no peer to reach it. Naming a cluster
// later is a configuration change (the maintainer, 2026-11-24).
void cluster_of_one(const dannan::config::Settings& settings, dannan::NodeConfig& node, const std::filesystem::path& state) {
  if (settings.text("cluster.key") || !settings.list("cluster.bootstrap").empty()) return;
  namespace fs = std::filesystem;
  const auto key = state / "cluster.key";
  if (!fs::exists(key)) {
    fs::create_directories(state);
    fs::permissions(state, fs::perms::owner_all, fs::perm_options::replace);
    const auto secret = dannan::identity::random_bytes(32);
    std::string text;
    for (const auto byte : secret) {
      static constexpr char kHex[] = "0123456789abcdef";
      text += kHex[byte >> 4];
      text += kHex[byte & 0x0f];
    }
    {
      std::ofstream out(key, std::ios::binary | std::ios::trunc);
      out << text << "\n";
      if (!out) throw std::runtime_error("cannot write " + key.string());
    }
    fs::permissions(key, fs::perms::owner_read | fs::perms::owner_write, fs::perm_options::replace);
  }
  node.key = dannan::identity::load_cluster_key(key);
  node.listen_host = "127.0.0.1";
  node.advertise_host = "127.0.0.1";
  node.port = 0;
}

// What serves, once the node has started: the pools, the services, the routes and the listeners,
// and the loops that keep the keys and the sessions current. One shared object: a loop's pending
// wait holds it, so a wait that completes after the stop still finds it whole.
class Serving : public std::enable_shared_from_this<Serving> {
 public:
  Serving(dannan::supervise::Program& program, Config config, std::shared_ptr<dannan::status::LogSink> log)
      : _program(program),
        _io(program.io()),
        _config(std::move(config)),
        _log(std::move(log)),
        _logger(_log, "node"),
        _blocking(kBlockingThreads),
        _hashing(kHashingThreads),
        _rotation(_io),
        _refresh(_io),
        _logout_tick(_io) {}

  // Builds everything and starts the listeners. Called on the main thread while the helper's io
  // threads run; a failure throws, and the helper stops the node in order (exit 1).
  void start();
  // The drain: Lugh says it is draining, and its listeners take no new connection.
  void drain();
  // After the drain: the loops end, the pools finish what they hold, and what still waits on the
  // store or the audit log is dropped, not left holding what holds it.
  void stop();
  // SIGHUP: the operator's certificate files read again, for the next handshake on every listener;
  // connections already open keep theirs. A failure keeps what was loaded and says which file (the
  // maintainer, 2026-11-13: operator-supplied files only).
  void reload();

 private:
  void rotate_when_due();
  void refresh_sessions();
  void deliver_logouts();

  dannan::supervise::Program& _program;
  boost::asio::io_context& _io;
  const Config _config;
  std::shared_ptr<dannan::status::LogSink> _log;
  dannan::status::ScopedLogger _logger;
  std::atomic<bool> _stopping{false};

  // Joined at the stop, after everything that suspends on them has finished.
  boost::asio::thread_pool _blocking;
  boost::asio::thread_pool _hashing;

  Services _services;
  std::shared_ptr<dannan::listen::Certificates> _certificates;
  std::shared_ptr<dannan::listen::Certificates> _mtls_certificates;
  std::shared_ptr<http::Throttle> _throttle;
  std::shared_ptr<http::Router> _router;
  std::shared_ptr<http::ClientAddress> _client_address;
  std::shared_ptr<oauth::TokenIssuer> _token_issuer;
  std::shared_ptr<oauth::DpopChecker> _dpop;

  // The routes, each registered with the router, which keeps them by reference.
  std::unique_ptr<http::HealthRoutes> _health;
  std::unique_ptr<api::UserRoutes> _user_routes;
  std::unique_ptr<api::GroupRoutes> _group_routes;
  std::unique_ptr<api::PolicyRoutes> _policy_routes;
  std::unique_ptr<api::ScopeRoutes> _scope_routes;
  std::unique_ptr<api::AppRoutes> _app_routes;
  std::unique_ptr<api::AuditRoutes> _audit_routes;
  std::unique_ptr<api::KeyRoutes> _key_routes;
  std::unique_ptr<api::MeRoutes> _me_routes;
  std::unique_ptr<api::SessionRoutes> _session_routes;
  std::unique_ptr<api::AppPasswordRoutes> _app_password_routes;
  std::unique_ptr<signin::Pages> _pages;
  std::unique_ptr<api::FactorRoutes> _factor_routes;
  std::unique_ptr<oauth::MetadataRoutes> _metadata_routes;
  std::unique_ptr<oauth::FlowRoutes> _flow_routes;
  std::unique_ptr<oauth::LogoutRoutes> _logout_routes;
  std::unique_ptr<api::LdapRoutes> _ldap_routes;
  std::shared_ptr<oauth::BackchannelLogout> _backchannel;

  std::shared_ptr<http::HttpServer> _server;
  std::shared_ptr<http::HttpServer> _mtls_server;
  std::vector<std::shared_ptr<ldap::LdapServer>> _ldap_servers;

  boost::asio::steady_timer _rotation;
  boost::asio::steady_timer _refresh;
  boost::asio::steady_timer _logout_tick;
};

void Serving::start() {
  const auto& time = _program.context().time().source();
  const auto& wall = dannan::contract::system_wall_clock();
  const std::shared_ptr<const system::Environment> environment(&dannan::config::process_environment(), [](const system::Environment*) {});

  _logger.info(std::string("Lugh ") + LUGH_VERSION);
  _logger.info(_config.path.empty() ? "No configuration file; defaults, environment and command line only" : "Configuration " + _config.path);

  auto files = std::make_shared<system::SystemFiles>(_blocking.get_executor());
  auto console = std::make_shared<system::SystemConsole>(_blocking.get_executor());
  auto keyrings = std::make_shared<keys::KeyringManager>(_log, files, console, environment, _config.state_directory, _hashing.get_executor());
  const Ports ports{_log, time, wall, files, console, keyrings, _blocking.get_executor(), _hashing.get_executor()};

  // The keyring, the store and the services, before anything is served: a node that cannot read
  // its tables whole does not serve.
  auto started = boost::asio::co_spawn(_io, lugh_start(ports, _config), boost::asio::use_future).get();
  if (!started.ok) throw std::runtime_error(started.error);
  _services = std::move(started.value);
  const auto& services = _services;

  // The operator's certificates, for Dannan's public listener: the main listener's, and the mTLS
  // one's with the client CA. A pair that cannot be read throws, naming the file.
  _certificates = std::make_shared<dannan::listen::Certificates>(dannan::listen::CertificatePaths{_config.tls_certificate, _config.tls_key, {}});
  if (_config.mtls_port != 0) {
    _mtls_certificates =
        std::make_shared<dannan::listen::Certificates>(dannan::listen::CertificatePaths{_config.tls_certificate, _config.tls_key, _config.tls_client_ca});
  }

  // A caller is a signed-in session; with an issuer, Lugh's own access tokens are callers too.
  // There is no other way in: the one credential Lugh is born with is root's password, made at
  // genesis, and it opens a session only through the sign-in pages.
  if (!_config.issuer.empty()) {
    _token_issuer = std::make_shared<oauth::TokenIssuer>(services.keys, _config.issuer, wall, time, services.directory, services.grants);
  }
  session::SessionCallers::BearerCheck bearer;
  _dpop = std::make_shared<oauth::DpopChecker>(time, wall);
  if (_token_issuer) {
    bearer = [issuer = _token_issuer, dpop = _dpop](const http::HttpRequest& request) { return oauth::api_caller(*issuer, *dpop, request); };
  }
  std::shared_ptr<http::CallerResolver> resolver = std::make_shared<session::SessionCallers>(services.sessions, bearer);

  // Route handlers run on the io threads: they are coroutines, and suspend on the pools rather than
  // block.
  _throttle = std::make_shared<http::Throttle>(time);
  _router = std::make_shared<http::Router>(_io.get_executor(), _throttle, resolver);
  _client_address = std::make_shared<http::ClientAddress>(_config.trusted_proxies);
  auto& router = *_router;

  _health = std::make_unique<http::HealthRoutes>();
  _health->register_routes(router);
  _user_routes = std::make_unique<api::UserRoutes>(services.directory, services.factors, services.authenticator, services.links, services.sessions);
  _user_routes->register_routes(router);
  _group_routes = std::make_unique<api::GroupRoutes>(services.directory);
  _group_routes->register_routes(router);
  _policy_routes = std::make_unique<api::PolicyRoutes>(services.policies, services.directory);
  _policy_routes->register_routes(router);
  _scope_routes = std::make_unique<api::ScopeRoutes>(services.grants);
  _scope_routes->register_routes(router);
  _app_routes = std::make_unique<api::AppRoutes>(services.apps);
  _app_routes->register_routes(router);
  _audit_routes = std::make_unique<api::AuditRoutes>(services.audit);
  _audit_routes->register_routes(router);
  _key_routes = std::make_unique<api::KeyRoutes>(services.keys);
  _key_routes->register_routes(router);
  _me_routes = std::make_unique<api::MeRoutes>(services.directory, services.sessions);
  _me_routes->register_routes(router);
  _session_routes = std::make_unique<api::SessionRoutes>(services.sessions, services.directory, services.passwords, services.authenticator);
  _session_routes->register_routes(router);
  _app_password_routes = std::make_unique<api::AppPasswordRoutes>(services.app_passwords);
  _app_password_routes->register_routes(router);
  auto pre_sessions = std::make_shared<session::PreSessions>(time, authn::Authenticator::Settings{}.lifetime);
  _pages = std::make_unique<signin::Pages>(services.authenticator, services.directory, services.sessions, pre_sessions);
  // A person's own factors, behind the re-authentication window (TODO/2026-11-15-self-factors.md).
  _factor_routes = std::make_unique<api::FactorRoutes>(services.sessions, std::make_shared<session::Reauthentications>(time), services.directory,
                                                       services.factors, services.authenticator, authn::Authenticator::Settings{}.issuer);
  // WebAuthn (P11): the RP ID is the issuer's host and the issuer's origin is where ceremonies come
  // from, so it is offered only when the issuer is set. The pages and the factor routes share one
  // set of challenges.
  if (const auto where = _config.issuer.empty() ? std::nullopt : client::https_target(_config.issuer)) {
    const auto origin = "https://" + where->host + (where->port == "443" ? std::string() : ":" + where->port);
    const auto challenges = std::make_shared<authn::Challenges>(time);
    _pages->webauthn({where->host, {origin}, "Lugh", challenges, services.factors});
    _factor_routes->webauthn({where->host, {origin}, "Lugh", challenges});
  } else {
    _logger.warn("No oauth.issuer: WebAuthn is not offered, so nobody can reach the phr level");
  }
  _pages->register_routes(router);
  _factor_routes->register_routes(router);
  _metadata_routes =
      std::make_unique<oauth::MetadataRoutes>(services.keys, oauth::MetadataRoutes::Settings{_config.issuer, _config.allow_client_secrets, _config.mtls_port});
  _metadata_routes->register_routes(router);
  if (_config.issuer.empty()) _logger.warn("No oauth.issuer: the OAuth metadata, the code flow and the token endpoint are not served");
  if (_token_issuer) {
    auto clients = std::make_shared<oauth::ClientAuthenticator>(services.apps, _hashing.get_executor(), wall, time, _config.issuer);
    auto refresh = std::make_shared<oauth::RefreshTokens>(services.store, wall, services.sessions, services.audit);
    _flow_routes =
        std::make_unique<oauth::FlowRoutes>(oauth::FlowRoutes::Parts{services.apps, services.directory, services.sessions, services.consents, _token_issuer,
                                                                     clients, refresh, _dpop, std::make_shared<oauth::DeviceGrants>(time), &time, &wall});
    _flow_routes->register_routes(router);
    _logout_routes = std::make_unique<oauth::LogoutRoutes>(services.apps, services.sessions, _token_issuer);
    _logout_routes->register_routes(router);
    _backchannel = std::make_shared<oauth::BackchannelLogout>(services.apps, _token_issuer, std::make_shared<http::HttpsOutbound>(_io, _config.outbound_ca),
                                                              services.audit, time, oauth::BackchannelLogout::Settings{});
    services.sessions->on_end([backchannel = _backchannel](const session::Session& session, const std::string&) { backchannel->session_ended(session); });
  }

  // POSIX numbers, whether or not LDAP is listening here.
  if (_config.ldap_uid_range) {
    services.directory->numbers_set(
        std::make_shared<directory::PosixNumbers>(services.store, directory::PosixNumbers::Range{_config.ldap_uid_range->first, _config.ldap_uid_range->second},
                                                  directory::PosixNumbers::Range{_config.ldap_gid_range->first, _config.ldap_gid_range->second}));
    _ldap_routes = std::make_unique<api::LdapRoutes>(services.directory);
    _ldap_routes->register_routes(router);
  }

  _server = std::make_shared<http::HttpServer>(_log, _io, _certificates, _client_address);
  // The router first, under the paths it owns; then the dashboard, when there is one, for every
  // other path; anything left is a 404.
  for (const auto* prefix : {"/health", "/ready", "/api", "/oauth2", "/.well-known", "/signin", "/signout"}) _server->middleware_add(router.middleware(prefix));
  if (!_config.static_directory.empty()) {
    const http::StaticSite site(http::StaticSite::read(_config.static_directory));
    _server->middleware_add(site.middleware());
    _logger.info("The dashboard: " + std::to_string(site.size()) + " files from " + _config.static_directory);
  } else {
    _logger.info("No static.directory: the dashboard is not served");
  }
  if (const auto listening = _server->listen(_config.address, _config.port); !listening.ok) throw std::runtime_error(listening.error);

  // The mTLS listener, when there is one: the same routes, and every connection asked for a client
  // certificate (RFC 8705).
  if (_config.mtls_port != 0) {
    _mtls_server = std::make_shared<http::HttpServer>(_log, _io, _mtls_certificates, _client_address, http::HttpPipeline::Limits{}, true);
    for (const auto* prefix : {"/health", "/ready", "/api", "/oauth2"}) _mtls_server->middleware_add(router.middleware(prefix));
    if (const auto listening = _mtls_server->listen(_config.address, _config.mtls_port); !listening.ok) throw std::runtime_error(listening.error);
  }

  // LDAP, a second front end on the directory (TODO/2026-11-04-ldap.md).
  if (_config.ldap_port != 0 || _config.ldap_starttls_port != 0) {
    ldap::Tree::Settings tree_settings;
    tree_settings.base_dn = _config.ldap_base_dn;
    tree_settings.home = _config.ldap_home;
    tree_settings.shell = _config.ldap_shell;
    tree_settings.primary_group = _config.ldap_primary_group;
    auto tree = std::make_shared<ldap::Tree>(services.directory, tree_settings);
    ldap::Operations::Settings operation_settings;
    operation_settings.vendor_version = LUGH_VERSION;
    operation_settings.extensions = {ldap::kStartTlsOid, ldap::kWhoAmIOid, ldap::kPasswordModifyOid};
    operation_settings.controls = {ldap::kPagedResultsOid, ldap::kAssertionOid};
    ldap::ConnectionParts parts;
    parts.binder = std::make_shared<ldap::Binder>(tree, services.directory, services.authenticator, services.app_passwords, services.grants, services.audit);
    parts.operations = std::make_shared<ldap::Operations>(tree, operation_settings);
    parts.writes = std::make_shared<ldap::Writes>(tree, services.directory, services.sessions, services.passwords, services.authenticator);
    parts.certificates = _certificates;
    parts.throttle = _throttle;
    parts.anonymous_bind = _config.ldap_anonymous_bind;
    parts.most_pending = _config.ldap_most_pending;
    parts.idle = std::chrono::seconds(_config.ldap_idle_seconds);
    for (const auto& [port, with_tls] : {std::pair{_config.ldap_port, true}, std::pair{_config.ldap_starttls_port, false}}) {
      if (port == 0) continue;
      auto listener = std::make_shared<ldap::LdapServer>(_log, _io, parts, with_tls);
      if (const auto listening = listener->listen(_config.address, port); !listening.ok) throw std::runtime_error(listening.error);
      _ldap_servers.push_back(std::move(listener));
    }
  }

  rotate_when_due();
  refresh_sessions();
  if (_backchannel) deliver_logouts();

  _server->start();
  if (_mtls_server) _mtls_server->start();
  for (const auto& one : _ldap_servers) one->start();
  _program.context().readiness().set("lugh.serving", dannan::status::Health::ready);
}

// Once an hour, a key that has signed for its time is replaced (the new one published for an hour
// before it signs). A failure is logged and tried again the next hour.
void Serving::rotate_when_due() {
  _rotation.expires_after(std::chrono::hours(1));
  _rotation.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
    if (ec || self->_stopping) return;
    self->_services.keys->rotate_due(kTransitionDeadline, self->_io.get_executor(), [self](Status rotated) {
      if (!rotated.ok) self->_logger.error("Key rotation: " + rotated.error);
      if (!self->_stopping) self->rotate_when_due();
    });
  });
}

// Every minute, each session's user and scopes are read again, and the sessions of users removed or
// disabled, and those expired, end.
void Serving::refresh_sessions() {
  _refresh.expires_after(std::chrono::minutes(1));
  _refresh.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
    if (ec || self->_stopping) return;
    self->_services.sessions->refresh(kTransitionDeadline, self->_io.get_executor(), [self](Status refreshed) {
      if (!refreshed.ok) self->_logger.error("Session refresh: " + refreshed.error);
      if (!self->_stopping) self->refresh_sessions();
    });
  });
}

// Every second, the back-channel logouts that are due. A post that is slow holds up no other.
void Serving::deliver_logouts() {
  _logout_tick.expires_after(std::chrono::seconds(1));
  _logout_tick.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
    if (ec || self->_stopping) return;
    self->_backchannel->deliver_due(kTransitionDeadline, self->_io.get_executor(), [](Status) {});
    self->deliver_logouts();
  });
}

void Serving::drain() {
  _logger.info("Stopping: the listeners take no new connection");
  _program.context().readiness().set("lugh.serving", dannan::status::Health::draining, "stopping");
  if (_server) _server->stop();
  if (_mtls_server) _mtls_server->stop();
  for (const auto& one : _ldap_servers) one->stop();
}

void Serving::stop() {
  _stopping = true;
  boost::asio::post(_io, [self = shared_from_this()] {
    self->_rotation.cancel();
    self->_refresh.cancel();
    self->_logout_tick.cancel();
  });
  _blocking.join();
  _hashing.join();
  if (_services.store) _services.store->abandon_waiters();
  if (_services.audit) _services.audit->abandon_pending();
}

void Serving::reload() {
  for (const auto& one : {_certificates, _mtls_certificates}) {
    if (!one) continue;
    try {
      one->reload();
      _logger.info("Certificates reloaded from " + one->paths().chain.string());
    } catch (const std::runtime_error& refused) {
      _logger.error(std::string("Certificates not reloaded, the old ones kept: ") + refused.what());
    }
  }
}

// The log for a command word, which runs before any node: the helper's settings, read the same way.
std::shared_ptr<dannan::status::LogSink> command_log(const dannan::config::Settings& settings) {
  return dannan::status::console_sink(dannan::status::parse_log_format(settings.text("log.format").value_or("text")),
                                      dannan::status::parse_log_level(settings.text("log.level").value_or("info")));
}

// `lugh-node init`, before any node: its own io_context and pools, as genesis needs nothing else.
int init(const dannan::config::Settings& settings) {
  const auto loaded = ConfigLoader::read(settings, ConfigLoader::Purpose::init);
  if (!loaded.ok) throw std::runtime_error(loaded.error);
  const auto& config = loaded.value;
  const auto log = command_log(settings);
  const std::shared_ptr<const system::Environment> environment(&dannan::config::process_environment(), [](const system::Environment*) {});

  boost::asio::io_context io_context;
  boost::asio::thread_pool blocking(kBlockingThreads);
  boost::asio::thread_pool hashing(kHashingThreads);
  // Joined last, after everything that suspends on them has finished.
  struct JoinPools {
    boost::asio::thread_pool& a;
    boost::asio::thread_pool& b;
    ~JoinPools() {
      a.join();
      b.join();
    }
  } join_pools{blocking, hashing};

  auto files = std::make_shared<system::SystemFiles>(blocking.get_executor());
  auto console = std::make_shared<system::SystemConsole>(blocking.get_executor());
  auto keyrings = std::make_shared<keys::KeyringManager>(log, files, console, environment, config.state_directory, hashing.get_executor());
  const Ports ports{log,
                    dannan::contract::steady_time_source(),
                    dannan::contract::system_wall_clock(),
                    files,
                    console,
                    keyrings,
                    blocking.get_executor(),
                    hashing.get_executor()};
  return run_until(io_context, run_init(config.passphrase, ports, config.state_directory));
}

}  // namespace

int main(int argc, char* argv[]) {
  // A core dump of an identity server is a copy of its keys, and so is a debugger attached to it.
  // The unit says LimitCORE=0 too; this covers a run outside it.
  if (const auto hardening = dannan::identity::harden_process(); !hardening.core_dumps_disabled || !hardening.attach_refused) {
    std::cerr << "warning: the process is not fully hardened: " << hardening.detail << "\n";
  }

  dannan::supervise::ProgramSpec spec;
  spec.name = "lugh-node";
  spec.prefix = "LUGH";
  spec.version = LUGH_VERSION;
  spec.default_config = ConfigLoader::kInstalledPath;
  spec.settings = [](dannan::config::Reader& reader) { ConfigLoader::add_settings(reader); };

  // Read and checked before any node is built, so a setting that cannot be used stops the start
  // (exit 2), naming it.
  Config config;
  std::shared_ptr<dannan::status::LogSink> log;
  spec.configure = [&](const dannan::config::Settings& settings, dannan::NodeConfig& node) {
    auto loaded = ConfigLoader::read(settings, ConfigLoader::Purpose::serve);
    if (!loaded.ok) throw std::runtime_error(loaded.error);
    config = std::move(loaded.value);
    if (node.state_path.empty()) node.state_path = config.state_directory;
    cluster_of_one(settings, node, node.state_path);
    log = node.log;
  };
  spec.commands["init"] = init;

  std::shared_ptr<Serving> serving;
  const auto code = dannan::supervise::run_node_program(argc, argv, std::move(spec), [&](dannan::supervise::Program& program) {
    serving = std::make_shared<Serving>(program, config, log);
    program.on_drain([&](dannan::contract::Deadline, std::function<void()> done) {
      if (serving) serving->drain();
      done();
    });
    program.on_stop([&] {
      if (serving) serving->stop();
      serving.reset();
    });
    program.on_reload([&] {
      if (serving) serving->reload();
    });
    program.on_exit([&] { dannan::status::ScopedLogger(log, "node").info("Stopped"); });
    serving->start();
  });
  return code;
}
