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
#include "lugh/api/audit_routes.h"
#include "lugh/api/group_routes.h"
#include "lugh/api/policy_routes.h"
#include "lugh/api/user_routes.h"
#include "lugh/audit/audit_log.h"
#include "lugh/authn/authenticator.h"
#include "lugh/authn/genesis.h"
#include "lugh/directory/directory.h"
#include "lugh/http/client_address.h"
#include "lugh/http/health_routes.h"
#include "lugh/http/http_server.h"
#include "lugh/http/rate_limiter.h"
#include "lugh/http/router.h"
#include "lugh/http/tls_context.h"
#include "lugh/keys/keyring_manager.h"
#include "lugh/node/cli.h"
#include "lugh/node/config.h"
#include "lugh/store/sealed_store.h"
#include "lugh/store/tables.h"
#include "lugh/system/system_console.h"
#include "lugh/system/system_environment.h"
#include "lugh/system/system_files.h"
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
  const auto indexed = directory::table_specs();
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
  const auto audit = co_await audit::AuditLog::open(ports.log, opened.value, ports.wall);
  if (!audit.ok) co_return failed(audit.error);

  auto directory = std::make_shared<directory::Directory>(ports.log, opened.value, ports.wall, audit.value);
  auto passwords = std::make_shared<authn::Passwords>(ports.log, opened.value, ports.wall, audit.value, ports.hashing, crypto::Argon2Costs{},
                                                      authn::PasswordRules{}, authn::BreachedPasswords{});
  auto links = std::make_shared<authn::EnrolmentLinks>(opened.value, ports.wall, directory, audit.value);
  const auto password = co_await authn::Genesis(directory, passwords, links, audit.value).run();
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
  auto audit = co_await audit::AuditLog::open(ports.log, services.store, ports.wall);
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
  services.policies = std::make_shared<authn::Policies>(store, services.directory, services.audit);
  services.links = std::make_shared<authn::EnrolmentLinks>(store, ports.wall, services.directory, services.audit);
  // Reached by the API now, and by the sign-in routes from P6.
  services.authenticator = std::make_shared<authn::Authenticator>(ports.log, ports.time, services.directory, passwords, services.factors, services.policies,
                                                                  services.links, services.audit, authn::Authenticator::Settings{});

  logger.info(std::to_string((co_await services.directory->users()).size()) + " users, " + std::to_string((co_await services.directory->groups()).size()) +
              " groups, " + std::to_string(services.audit->size()) + " audit entries");
  co_return Answer::success(std::move(services));
}

int run(const cli::Options& options) {
  // What is said before the configuration is read goes to stderr at info; then the node's
  // sink, at the configured level, takes over.
  std::shared_ptr<dannan::status::LogSink> log = std::make_shared<dannan::status::ConsoleSink>();
  dannan::status::ScopedLogger logger(log, "node");

  // The node's clocks: Dannan's, one of each for the process.
  const auto& time = dannan::contract::steady_time_source();
  const auto& wall = dannan::contract::system_wall_clock();
  auto environment = std::make_shared<system::SystemEnvironment>();

  logger.info(std::string("Lugh ") + LUGH_VERSION);

  ConfigLoader loader(environment, ConfigLoader::kInstalledPath);
  const auto loaded = loader.load(options);
  for (const auto& warning : loader.warnings()) logger.warn(warning);
  if (!loaded.ok) {
    logger.error(loaded.error);
    return 1;
  }
  const auto& config = loaded.value;

  log = dannan::status::console_sink(config.log_format, config.log_level);
  logger = dannan::status::ScopedLogger(log, "node");
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

  if (options.command == cli::Command::init) return run_until(io_context, run_init(options, ports, config.state_directory));

  auto started = run_until(io_context, start(ports, config));
  if (!started.ok) {
    logger.error(started.error);
    return 1;
  }
  const auto& services = started.value;

  const auto tls = http::TlsContext::server(config.tls_certificate, config.tls_key);
  if (!tls.ok) {
    logger.error(tls.error);
    return 1;
  }

  // Nothing resolves a caller until sessions and OAuth tokens arrive (P6), so until then
  // the API answers 401 to everyone. There is no other way in: the one credential Lugh is
  // born with is root's password, made at genesis.
  std::shared_ptr<http::CallerResolver> resolver;

  // Route handlers run on the io_context's own threads: they are coroutines, and suspend
  // on the pools rather than block.
  auto throttle = std::make_shared<http::Throttle>(time);
  auto router = std::make_shared<http::Router>(io_context.get_executor(), throttle, resolver);
  auto client_address = std::make_shared<http::ClientAddress>(config.trusted_proxies);

  http::HealthRoutes health;
  health.register_routes(*router);
  api::UserRoutes user_routes(services.directory, services.factors, services.authenticator, services.links);
  user_routes.register_routes(*router);
  api::GroupRoutes group_routes(services.directory);
  group_routes.register_routes(*router);
  api::PolicyRoutes policy_routes(services.policies, services.directory);
  policy_routes.register_routes(*router);
  api::AuditRoutes audit_routes(services.audit);
  audit_routes.register_routes(*router);

  auto server = std::make_shared<http::HttpServer>(log, io_context, tls.value, client_address);

  // The router first, under the paths it owns; anything left is a 404. The dashboard
  // joins the chain after the API, in P7.
  for (const auto* prefix : {"/health", "/ready", "/api"}) server->middleware_add(router->middleware(prefix));

  if (const auto listening = server->listen(config.address, config.port); !listening.ok) {
    logger.error(listening.error);
    return 1;
  }

  boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
  signals.async_wait([&](const boost::system::error_code& ec, int number) {
    if (ec) return;
    logger.info("Stopping on " + signal_name(number));
    server->stop();
    io_context.stop();
  });

  server->start();

  std::vector<std::thread> threads;
  for (unsigned i = 1; i < config.threads; ++i) threads.emplace_back([&io_context] { io_context.run(); });
  io_context.run();
  for (auto& thread : threads) thread.join();

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

  if (!options.ok) {
    std::cerr << options.error << "\n\n" << lugh::cli::usage();
    return 2;
  }
  if (options.help) {
    std::cout << lugh::cli::usage();
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
