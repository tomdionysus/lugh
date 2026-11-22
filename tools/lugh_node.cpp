//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

// The composition root: the one file that names every concrete class. It builds the
// adapters and the pools they block on, opens the keyring and the store in a coroutine on
// the io_context, starts the server, waits for SIGTERM or SIGINT, and stops in reverse.
// `lugh-node init` is genesis: the keyring, the store, and root.

#include <unistd.h>

#include <boost/asio.hpp>
#include <cerrno>
#include <csignal>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "dannan/identity/secure_memory.h"
#include "dannan/status/log.h"
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
#include "lugh/node/cli.h"
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

std::string signal_name(int number) {
  if (number == SIGTERM) return "SIGTERM";
  if (number == SIGINT) return "SIGINT";
  return "signal " + std::to_string(number);
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
Task<int> run_init(cli::Options options, Ports ports, std::string state_directory) {
  auto& keyrings = *ports.keyrings;
  const dannan::status::ScopedLogger logger(ports.log, "node");
  if (options.passphrase) {
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
Task<Result<Services>> start(Ports ports, Config config) {
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

int run(const cli::Options& options) {
  // What is said before the configuration is read goes to stderr at info; then the node's
  // sink, at the configured level, takes over, under the same logger (Dannan's SwappableSink).
  const auto log = std::make_shared<dannan::status::SwappableSink>(std::make_shared<dannan::status::ConsoleSink>());
  dannan::status::ScopedLogger logger(log, "node");

  // The node's clocks: Dannan's, one of each for the process.
  const auto& time = dannan::contract::steady_time_source();
  const auto& wall = dannan::contract::system_wall_clock();
  // The process's environment, Dannan's, held by everything that reads it.
  const std::shared_ptr<const system::Environment> environment(&dannan::config::process_environment(), [](const system::Environment*) {});

  logger.info(std::string("Lugh ") + LUGH_VERSION);

  ConfigLoader loader(environment, ConfigLoader::kInstalledPath);
  const auto loaded = loader.load(options);
  for (const auto& warning : loader.warnings()) logger.warn(warning);
  if (!loaded.ok) {
    logger.error(loaded.error);
    return 1;
  }
  const auto& config = loaded.value;

  log->set(dannan::status::console_sink(config.log_format, config.log_level));
  logger.info(config.path.empty() ? "No configuration file; defaults, environment and command line only" : "Configuration " + config.path);

  boost::asio::io_context io_context(static_cast<int>(config.threads));
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
  const Ports ports{log, time, wall, files, console, keyrings, blocking.get_executor(), hashing.get_executor()};

  if (config.command == cli::Command::init) return run_until(io_context, run_init(options, ports, config.state_directory));

  auto started = run_until(io_context, start(ports, config));
  if (!started.ok) {
    logger.error(started.error);
    return 1;
  }
  const auto& services = started.value;

  // The operator's certificates, for Dannan's public listener: the main listener's, and the mTLS
  // one's with the client CA.
  std::shared_ptr<dannan::listen::Certificates> certificates;
  std::shared_ptr<dannan::listen::Certificates> mtls_certificates;
  try {
    certificates = std::make_shared<dannan::listen::Certificates>(dannan::listen::CertificatePaths{config.tls_certificate, config.tls_key, {}});
    if (config.mtls_port != 0) {
      mtls_certificates =
          std::make_shared<dannan::listen::Certificates>(dannan::listen::CertificatePaths{config.tls_certificate, config.tls_key, config.tls_client_ca});
    }
  } catch (const std::runtime_error& refused) {
    logger.error(refused.what());
    return 1;
  }

  // A caller is a signed-in session; OAuth tokens join it with the token endpoint (P6, O7).
  // There is no other way in: the one credential Lugh is born with is root's password, made
  // at genesis, and it opens a session only through the sign-in pages.
  // With an issuer, Lugh's own access tokens are callers too.
  std::shared_ptr<oauth::TokenIssuer> token_issuer;
  if (!config.issuer.empty()) {
    token_issuer = std::make_shared<oauth::TokenIssuer>(services.keys, config.issuer, wall, time, services.directory, services.grants);
  }
  session::SessionCallers::BearerCheck bearer;
  const auto dpop = std::make_shared<oauth::DpopChecker>(time, wall);
  if (token_issuer) bearer = [token_issuer, dpop](const http::HttpRequest& request) { return oauth::api_caller(*token_issuer, *dpop, request); };
  std::shared_ptr<http::CallerResolver> resolver = std::make_shared<session::SessionCallers>(services.sessions, bearer);

  // Route handlers run on the io_context's own threads: they are coroutines, and suspend
  // on the pools rather than block.
  auto throttle = std::make_shared<http::Throttle>(time);
  auto router = std::make_shared<http::Router>(io_context.get_executor(), throttle, resolver);
  auto client_address = std::make_shared<http::ClientAddress>(config.trusted_proxies);

  http::HealthRoutes health;
  health.register_routes(*router);
  api::UserRoutes user_routes(services.directory, services.factors, services.authenticator, services.links, services.sessions);
  user_routes.register_routes(*router);
  api::GroupRoutes group_routes(services.directory);
  group_routes.register_routes(*router);
  api::PolicyRoutes policy_routes(services.policies, services.directory);
  policy_routes.register_routes(*router);
  api::ScopeRoutes scope_routes(services.grants);
  scope_routes.register_routes(*router);
  api::AppRoutes app_routes(services.apps);
  app_routes.register_routes(*router);
  api::AuditRoutes audit_routes(services.audit);
  audit_routes.register_routes(*router);
  api::KeyRoutes key_routes(services.keys);
  key_routes.register_routes(*router);
  api::MeRoutes me_routes(services.directory, services.sessions);
  me_routes.register_routes(*router);
  api::SessionRoutes session_routes(services.sessions, services.directory, services.passwords, services.authenticator);
  session_routes.register_routes(*router);
  api::AppPasswordRoutes app_password_routes(services.app_passwords);
  app_password_routes.register_routes(*router);
  auto pre_sessions = std::make_shared<session::PreSessions>(time, authn::Authenticator::Settings{}.lifetime);
  signin::Pages pages(services.authenticator, services.directory, services.sessions, pre_sessions);
  // A person's own factors, behind the re-authentication window (TODO/2026-11-15-self-factors.md).
  api::FactorRoutes factor_routes(services.sessions, std::make_shared<session::Reauthentications>(time), services.directory, services.factors,
                                  services.authenticator, authn::Authenticator::Settings{}.issuer);
  // WebAuthn (P11): the RP ID is the issuer's host and the issuer's origin is where ceremonies
  // come from, so it is offered only when the issuer is set. The pages and the factor routes share
  // one set of challenges.
  if (const auto where = config.issuer.empty() ? std::nullopt : client::https_target(config.issuer)) {
    const auto origin = "https://" + where->host + (where->port == "443" ? std::string() : ":" + where->port);
    const auto challenges = std::make_shared<authn::Challenges>(time);
    pages.webauthn({where->host, {origin}, "Lugh", challenges, services.factors});
    factor_routes.webauthn({where->host, {origin}, "Lugh", challenges});
  } else {
    logger.warn("No oauth.issuer: WebAuthn is not offered, so nobody can reach the phr level");
  }
  pages.register_routes(*router);
  factor_routes.register_routes(*router);
  oauth::MetadataRoutes metadata_routes(services.keys, {config.issuer, config.allow_client_secrets, config.mtls_port});
  metadata_routes.register_routes(*router);
  if (config.issuer.empty()) logger.warn("No oauth.issuer: the OAuth metadata, the code flow and the token endpoint are not served");
  std::unique_ptr<oauth::FlowRoutes> flow_routes;
  std::unique_ptr<oauth::LogoutRoutes> logout_routes;
  std::shared_ptr<oauth::BackchannelLogout> backchannel;
  if (token_issuer) {
    auto clients = std::make_shared<oauth::ClientAuthenticator>(services.apps, ports.hashing, wall, time, config.issuer);
    auto refresh = std::make_shared<oauth::RefreshTokens>(services.store, wall, services.sessions, services.audit);
    flow_routes =
        std::make_unique<oauth::FlowRoutes>(oauth::FlowRoutes::Parts{services.apps, services.directory, services.sessions, services.consents, token_issuer,
                                                                     clients, refresh, dpop, std::make_shared<oauth::DeviceGrants>(time), &time, &wall});
    flow_routes->register_routes(*router);
    logout_routes = std::make_unique<oauth::LogoutRoutes>(services.apps, services.sessions, token_issuer);
    logout_routes->register_routes(*router);
    backchannel = std::make_shared<oauth::BackchannelLogout>(services.apps, token_issuer, std::make_shared<http::HttpsOutbound>(io_context, config.outbound_ca),
                                                             services.audit, time, oauth::BackchannelLogout::Settings{});
    services.sessions->on_end([backchannel](const session::Session& session, const std::string&) { backchannel->session_ended(session); });
  }

  auto server = std::make_shared<http::HttpServer>(log, io_context, certificates, client_address);

  // The router first, under the paths it owns; then the dashboard, when there is one, for every
  // other path; anything left is a 404.
  for (const auto* prefix : {"/health", "/ready", "/api", "/oauth2", "/.well-known", "/signin", "/signout"}) server->middleware_add(router->middleware(prefix));
  if (!config.static_directory.empty()) {
    try {
      const http::StaticSite site(http::StaticSite::read(config.static_directory));
      server->middleware_add(site.middleware());
      logger.info("The dashboard: " + std::to_string(site.size()) + " files from " + config.static_directory);
    } catch (const std::exception& refused) {
      logger.error(refused.what());
      return 1;
    }
  } else {
    logger.info("No static.directory: the dashboard is not served");
  }

  if (const auto listening = server->listen(config.address, config.port); !listening.ok) {
    logger.error(listening.error);
    return 1;
  }

  // The mTLS listener, when there is one: the same routes, and every connection asked for a
  // client certificate (RFC 8705).
  std::shared_ptr<http::HttpServer> mtls_server;
  if (config.mtls_port != 0) {
    mtls_server = std::make_shared<http::HttpServer>(log, io_context, mtls_certificates, client_address, http::HttpPipeline::Limits{}, true);
    for (const auto* prefix : {"/health", "/ready", "/api", "/oauth2"}) mtls_server->middleware_add(router->middleware(prefix));
    if (const auto listening = mtls_server->listen(config.address, config.mtls_port); !listening.ok) {
      logger.error(listening.error);
      return 1;
    }
  }

  // Once an hour, a key that has signed for its time is replaced (the new one published for
  // an hour before it signs). A failure is logged and tried again the next hour.
  boost::asio::steady_timer rotation(io_context);
  std::function<void()> rotate_when_due = [&] {
    rotation.expires_after(std::chrono::hours(1));
    rotation.async_wait([&](const boost::system::error_code& ec) {
      if (ec) return;
      services.keys->rotate_due(kTransitionDeadline, io_context.get_executor(), [&](Status rotated) {
        if (!rotated.ok) logger.error("Key rotation: " + rotated.error);
        rotate_when_due();
      });
    });
  };
  rotate_when_due();

  // Every minute, each session's user and scopes are read again, and the sessions of users
  // removed or disabled, and those expired, end.
  boost::asio::steady_timer refresh(io_context);
  std::function<void()> refresh_sessions = [&] {
    refresh.expires_after(std::chrono::minutes(1));
    refresh.async_wait([&](const boost::system::error_code& ec) {
      if (ec) return;
      services.sessions->refresh(kTransitionDeadline, io_context.get_executor(), [&](Status refreshed) {
        if (!refreshed.ok) logger.error("Session refresh: " + refreshed.error);
        refresh_sessions();
      });
    });
  };
  refresh_sessions();

  // Every second, the back-channel logouts that are due. A post that is slow holds up no other.
  boost::asio::steady_timer logout_tick(io_context);
  std::function<void()> deliver_logouts = [&] {
    logout_tick.expires_after(std::chrono::seconds(1));
    logout_tick.async_wait([&](const boost::system::error_code& ec) {
      if (ec) return;
      backchannel->deliver_due(kTransitionDeadline, io_context.get_executor(), [](Status) {});
      deliver_logouts();
    });
  };
  if (backchannel) deliver_logouts();

  // POSIX numbers, whether or not LDAP is listening here.
  std::unique_ptr<api::LdapRoutes> ldap_routes;
  if (config.ldap_uid_range) {
    services.directory->numbers_set(
        std::make_shared<directory::PosixNumbers>(services.store, directory::PosixNumbers::Range{config.ldap_uid_range->first, config.ldap_uid_range->second},
                                                  directory::PosixNumbers::Range{config.ldap_gid_range->first, config.ldap_gid_range->second}));
    ldap_routes = std::make_unique<api::LdapRoutes>(services.directory);
    ldap_routes->register_routes(*router);
  }

  // LDAP, a second front end on the directory (TODO/2026-11-04-ldap.md).
  std::vector<std::shared_ptr<ldap::LdapServer>> ldap_servers;
  if (config.ldap_port != 0 || config.ldap_starttls_port != 0) {
    ldap::Tree::Settings tree_settings;
    tree_settings.base_dn = config.ldap_base_dn;
    tree_settings.home = config.ldap_home;
    tree_settings.shell = config.ldap_shell;
    tree_settings.primary_group = config.ldap_primary_group;
    auto tree = std::make_shared<ldap::Tree>(services.directory, tree_settings);
    ldap::Operations::Settings operation_settings;
    operation_settings.vendor_version = LUGH_VERSION;
    operation_settings.extensions = {ldap::kStartTlsOid, ldap::kWhoAmIOid, ldap::kPasswordModifyOid};
    operation_settings.controls = {ldap::kPagedResultsOid, ldap::kAssertionOid};
    ldap::ConnectionParts parts;
    parts.binder = std::make_shared<ldap::Binder>(tree, services.directory, services.authenticator, services.app_passwords, services.grants, services.audit);
    parts.operations = std::make_shared<ldap::Operations>(tree, operation_settings);
    parts.writes = std::make_shared<ldap::Writes>(tree, services.directory, services.sessions, services.passwords, services.authenticator);
    parts.certificates = certificates;
    parts.throttle = throttle;
    parts.anonymous_bind = config.ldap_anonymous_bind;
    parts.most_pending = config.ldap_most_pending;
    parts.idle = std::chrono::seconds(config.ldap_idle_seconds);
    const auto add_listener = [&](std::uint16_t port, bool with_tls) {
      if (port == 0) return true;
      auto listener = std::make_shared<ldap::LdapServer>(log, io_context, parts, with_tls);
      if (const auto listening = listener->listen(config.address, port); !listening.ok) {
        logger.error(listening.error);
        return false;
      }
      ldap_servers.push_back(std::move(listener));
      return true;
    };
    if (!add_listener(config.ldap_port, true) || !add_listener(config.ldap_starttls_port, false)) return 1;
  }

  // SIGHUP: the operator's certificate files read again (renewed by whatever the host runs), for the
  // next handshake on every listener; connections already open keep theirs. A failure keeps what
  // was loaded and says which file (the maintainer, 2026-11-13: operator-supplied files only).
  boost::asio::signal_set reloads(io_context, SIGHUP);
  std::function<void()> reload_on_hangup = [&] {
    reloads.async_wait([&](const boost::system::error_code& ec, int) {
      if (ec) return;
      for (const auto& one : {certificates, mtls_certificates}) {
        if (!one) continue;
        try {
          one->reload();
          logger.info("Certificates reloaded from " + one->paths().chain.string());
        } catch (const std::runtime_error& refused) {
          logger.error(std::string("Certificates not reloaded, the old ones kept: ") + refused.what());
        }
      }
      reload_on_hangup();
    });
  };
  reload_on_hangup();

  boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
  signals.async_wait([&](const boost::system::error_code& ec, int number) {
    if (ec) return;
    logger.info("Stopping on " + signal_name(number));
    reloads.cancel();
    server->stop();
    if (mtls_server) mtls_server->stop();
    for (const auto& one : ldap_servers) one->stop();
    io_context.stop();
  });

  server->start();
  if (mtls_server) mtls_server->start();
  for (const auto& one : ldap_servers) one->start();

  std::vector<std::thread> threads;
  for (unsigned i = 1; i < config.threads; ++i) threads.emplace_back([&io_context] { io_context.run(); });
  io_context.run();
  for (auto& thread : threads) thread.join();

  // Nothing runs the io_context now. What was still waiting is dropped, not left holding what
  // holds it.
  services.store->abandon_waiters();
  services.audit->abandon_pending();
  logger.info("Stopped");
  return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
  // A core dump of an identity server is a copy of its keys, and so is a debugger attached
  // to it. The unit says LimitCORE=0 too; this covers a run outside it.
  if (const auto hardening = dannan::identity::harden_process(); !hardening.core_dumps_disabled || !hardening.attach_refused) {
    std::cerr << "warning: the process is not fully hardened: " << hardening.detail << "\n";
  }

  const auto options = lugh::cli::parse(argc, argv);

  if (options.help) {
    std::cout << lugh::cli::usage(lugh::ConfigLoader::describe());
    return 0;
  }
  if (options.version) {
    std::cout << LUGH_VERSION << "\n";
    return 0;
  }

  try {
    return run(options);
  } catch (const std::exception& e) {
    std::cerr << "Failed: " << e.what() << "\n";
    return 1;
  }
}
