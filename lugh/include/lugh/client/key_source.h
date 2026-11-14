//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"
#include "lugh/client/https.h"
#include "lugh/client/verifier.h"

// Where a Verifier's keys come from over HTTPS (TODO/2026-11-14-p10-plan.md, P10.2): for each
// trusted issuer, its discovery document (OpenID Connect Discovery 1.0, section 4), whose issuer
// must be the one asked for (4.3) and whose jwks_uri must be https, then that JWKS, handed to the
// verifier. Fetched at start, again on a schedule, and when the verifier meets a token its keys
// cannot check (at most once a gap per issuer, so a stream of forged kids costs one fetch a
// minute). A failure keeps the last good keys and is tried again after a backoff that doubles to a
// ceiling; each issuer's state is visible (waiting for its first keys, fresh, or stale since a
// failure, with the last error), and refresh_now() is the operator's action (Macha's disciplines:
// backoff, a budget, a visible parked state, an operator action). Timers run on a strand of the
// caller's executor and decide by the injected TimeSource, so tests step time. Thread-safe.
namespace lugh::client {

class HttpsKeySource : public std::enable_shared_from_this<HttpsKeySource> {
 public:
  struct Settings {
    // How often keys are fetched when nothing prompts it.
    std::chrono::seconds refresh{3600};
    // The least time between two fetches for an issuer that a refused token prompts.
    std::chrono::seconds missing_gap{60};
    // The wait after a first failure, doubling with each one after it, to the ceiling.
    std::chrono::seconds first_backoff{5};
    std::chrono::seconds most_backoff{300};
    // How long one fetch (discovery and JWKS, each) may take.
    Deadline fetch_deadline{std::chrono::seconds(10)};
  };

  enum class State { waiting, fresh, stale };

  struct IssuerStatus {
    std::string issuer;
    State state = State::waiting;
    std::size_t keys = 0;
    std::uint32_t failures = 0;
    std::string last_error;
  };

  // The verifier, the client and the time source outlive this. Hands the verifier its hint.
  static std::shared_ptr<HttpsKeySource> make(Verifier& verifier, Https& https, Executor executor, const dannan::contract::TimeSource& time, Settings settings);

  // Fetches every issuer's keys at once, then keeps them fresh until stop().
  void start();
  // Stops the schedule and the verifier's hint; a fetch under way still hands in its keys, and
  // nothing more is fetched. The verifier keeps the keys it has.
  void stop();
  // The operator's action: every issuer fetched now, whatever its backoff.
  void refresh_now();

  std::vector<IssuerStatus> status() const;

 private:
  struct Issuer {
    IssuerStatus status;
    dannan::contract::TimePoint due{};
    dannan::contract::TimePoint last_attempt{};
    bool attempted = false;
    bool in_flight = false;
  };

  HttpsKeySource(Verifier& verifier, Https& https, Executor executor, const dannan::contract::TimeSource& time, Settings settings);

  // On the strand.
  void _tick();
  void _arm();
  void _fetch(std::size_t index);
  void _fetched(std::size_t index, std::string error, std::size_t keys);
  void _missing(const std::string& issuer);

  Verifier& _verifier;
  Https& _https;
  boost::asio::strand<Executor> _strand;
  const dannan::contract::TimeSource& _time;
  const Settings _settings;
  boost::asio::steady_timer _timer;

  mutable dannan::contract::Mutex _mutex;
  std::vector<Issuer> _issuers DANNAN_GUARDED_BY(_mutex);
  bool _running DANNAN_GUARDED_BY(_mutex) = false;
};

}  // namespace lugh::client
