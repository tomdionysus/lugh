// The composition root: the one file that names every concrete class. It builds the
// adapters, then everything that depends on them, starts the server, waits for SIGTERM or
// SIGINT, and stops in reverse.

#include <sys/resource.h>

#include <boost/asio.hpp>
#include <csignal>
#include <exception>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "build_version.h"
#include "cli.h"
#include "config.h"
#include "http/client_address.h"
#include "http/health_routes.h"
#include "http/http_server.h"
#include "http/rate_limiter.h"
#include "http/router.h"
#include "http/tls_context.h"
#include "loggers/logger_stdio.h"
#include "system/system_clock.h"
#include "system/system_environment.h"
#include "system/system_random.h"

namespace {

using namespace lugh;

std::string signal_name(int number) {
  if (number == SIGTERM) return "SIGTERM";
  if (number == SIGINT) return "SIGINT";
  return "signal " + std::to_string(number);
}

// A core dump of an identity server is a copy of its keys. The unit says LimitCORE=0 too;
// this covers a run outside it.
void refuse_core_dumps() {
  rlimit none{0, 0};
  setrlimit(RLIMIT_CORE, &none);
}

int run(const cli::Options& options) {
  auto logger = std::make_shared<loggers::LoggerStdIO>(loggers::INFO, std::cerr);
  auto clock = std::make_shared<system::SystemClock>();
  auto environment = std::make_shared<system::SystemEnvironment>();
  auto random = std::make_shared<system::SystemRandom>();

  logger->info(std::string("Lugh ") + LUGH_VERSION);

  ConfigLoader loader(environment, ConfigLoader::kInstalledPath);
  const auto loaded = loader.load(options);
  for (const auto& warning : loader.warnings()) logger->warn(warning);
  if (!loaded.ok) {
    logger->error(loaded.error);
    return 1;
  }
  const auto& config = loaded.value;

  logger->set_format(config.log_format);
  logger->set_level(config.log_level);
  logger->info(config.path.empty() ? "No configuration file; defaults, environment and command line only" : "Configuration " + config.path);

  const auto tls = http::TlsContext::server(config.tls_certificate, config.tls_key);
  if (!tls.ok) {
    logger->error(tls.error);
    return 1;
  }

  boost::asio::io_context io_context(static_cast<int>(config.threads));

  auto throttle = std::make_shared<http::Throttle>(clock);
  auto router = std::make_shared<http::Router>(throttle);
  auto client_address = std::make_shared<http::ClientAddress>(config.trusted_proxies);

  http::HealthRoutes health;
  health.register_routes(*router);

  auto server = std::make_shared<http::HttpServer>(logger, io_context, tls.value, client_address);

  // The router first, under the paths it owns; anything left is a 404. The dashboard
  // joins the chain after the API, in P7.
  for (const auto* prefix : {"/health", "/ready"}) server->middleware_add(router->middleware(prefix));

  if (const auto listening = server->listen(config.address, config.port); !listening.ok) {
    logger->error(listening.error);
    return 1;
  }

  boost::asio::signal_set signals(io_context, SIGINT, SIGTERM);
  signals.async_wait([&](const boost::system::error_code& ec, int number) {
    if (ec) return;
    logger->info("Stopping on " + signal_name(number));
    server->stop();
    io_context.stop();
  });

  server->start();

  std::vector<std::thread> threads;
  for (unsigned i = 1; i < config.threads; ++i) threads.emplace_back([&io_context] { io_context.run(); });
  io_context.run();
  for (auto& thread : threads) thread.join();

  logger->info("Stopped");
  return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
  refuse_core_dumps();

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
