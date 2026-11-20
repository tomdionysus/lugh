//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "dannan/contract/thread_safety.h"
#include "dannan/contract/time_source.h"
#include "dannan/sched/retry.h"
#include "lugh/client/https.h"
#include "lugh/client/key_source.h"
#include "lugh/client/oauth_client.h"
#include "lugh/client/tokens.h"
#include "lugh/client/verifier.h"
#include "lugh/core/completion.h"
#include "lugh/core/outcome.h"

// What a service that trusts Lugh needs, whole, so each keeps none of its own (the stack's
// placement plan, items 50, 53 and S10; the maintainer, 2026-11-20: the lower of two projects that
// depend on each other keeps what both need). Louhi's and Lir's first copies were the model.
namespace lugh::client {

// An issuer's endpoints from its discovery document (OpenID Connect Discovery 1.0, section 4),
// which must name the issuer asked for (4.3). Refused for a document that is not that
// issuer's or not usable, failed when it could not be read.
void discover(Https& https, const std::string& issuer, Deadline deadline, Executor executor, Done<Outcome<Endpoints>> done);

// The longest Authorization header value a token is taken from, Louhi's bound. Lugh's issuer is
// to refuse an access token that would not fit (TODO/2026-11-20-dependants.md, item 8).
inline constexpr std::size_t kMostAuthorizationBytes = 16 * 1024;

// The token in an Authorization header's value, `Bearer <token>` (RFC 6750 section 2.1): the
// scheme in any case, one or more spaces, then a b64token. Nothing for another scheme, a
// malformed token or a value over kMostAuthorizationBytes.
std::optional<std::string_view> bearer_token(std::string_view authorization);

// An API's side: access tokens checked offline against keys fetched from each trusted issuer
// and kept fresh (Verifier and HttpsKeySource), for one audience. Thread-safe; verify() never
// waits.
class RelyingParty {
 public:
  struct Settings {
    // Each trusted Lugh, as its tokens name it (iss).
    std::vector<std::string> issuers;
    // What a token must be for (aud).
    std::string audience;
    // The roots the issuers' HTTPS certificates chain to; empty: the system's.
    std::string ca_path;
    HttpsKeySource::Settings keys;
  };

  // The io context and clocks outlive this. Throws std::invalid_argument for no issuers or no
  // audience, and std::runtime_error for roots that cannot be read.
  RelyingParty(boost::asio::io_context& io, Settings settings, const dannan::contract::TimeSource& time, const dannan::contract::WallClock& wall);
  // As above, over an Https a test or a host supplies, which outlives this.
  RelyingParty(Https& https, Executor executor, Settings settings, const dannan::contract::TimeSource& time, const dannan::contract::WallClock& wall);
  ~RelyingParty();
  RelyingParty(const RelyingParty&) = delete;
  RelyingParty& operator=(const RelyingParty&) = delete;

  // Fetches every issuer's keys now and keeps them fresh until stop(). Until an issuer's keys
  // come, its tokens are refused. Waits on nothing.
  void start();
  void stop();

  // An access token for this audience, or why not.
  std::variant<AccessToken, std::string> verify(std::string_view token) const;
  // The same, from an Authorization header's value.
  std::variant<AccessToken, std::string> verify_header(std::string_view authorization) const;

  const Verifier& verifier() const noexcept { return _verifier; }
  std::vector<HttpsKeySource::IssuerStatus> status() const { return _keys->status(); }

 private:
  const Settings _settings;
  std::unique_ptr<HttpsClient> _owned;
  Verifier _verifier;
  std::shared_ptr<HttpsKeySource> _keys;
};

// A service's own access token, by the client-credentials grant (RFC 6749 section 4.4),
// proving itself by private_key_jwt or client_secret_basic. Fetched at start and again when
// two thirds of its life has passed (never sooner than kLeastRefresh), so current() answers at
// once with the newest one. A failure keeps the token held and tries the next issuer, in the
// order given, after a back-off that never parks (5 seconds doubling to 5 minutes): any one
// Lugh down is not the service's problem. Each issuer's discovery is read once it is first
// tried. Timers run on a strand of the caller's executor and decide by the injected
// TimeSource, so tests step time. Thread-safe.
class TokenSource : public std::enable_shared_from_this<TokenSource> {
 public:
  static constexpr std::chrono::seconds kLeastRefresh{10};

  struct Settings {
    // The issuers to ask, in order, each as its tokens name it. Each knows the client.
    std::vector<std::string> issuers;
    ClientIdentity identity;
    // Empty: every scope the client is granted.
    std::vector<std::string> scopes;
    // How long one request (discovery or the token) may take.
    Deadline step_deadline{std::chrono::seconds(30)};
  };

  struct Status {
    // The issuer the token held came from; empty before the first.
    std::string issuer;
    bool has_token = false;
    std::uint32_t failures = 0;
    std::string last_error;
  };

  // `https` and the clocks outlive this. Throws std::invalid_argument for no issuers, or an
  // identity that cannot sign in by private_key_jwt or client_secret_basic.
  static std::shared_ptr<TokenSource> make(Https& https, Executor executor, Settings settings, const dannan::contract::TimeSource& time,
                                           const dannan::contract::WallClock& wall);

  // Each waits on nothing. Nothing is asked of an issuer after stop(), and an answer that
  // comes after it is dropped.
  void start();
  void stop();
  // The newest token, or nothing before the first came. Never waits.
  std::optional<std::string> current() const;
  Status status() const;

 private:
  TokenSource(Https& https, Executor executor, Settings settings, const dannan::contract::TimeSource& time, const dannan::contract::WallClock& wall);

  // On the strand.
  void _fetch();
  void _discovered(std::size_t index, Outcome<Endpoints> found);
  void _failed(std::string why);
  void _later(std::chrono::milliseconds delay);
  void _wait();

  Https& _https;
  const Settings _settings;
  const dannan::contract::TimeSource& _time;
  const dannan::contract::WallClock& _wall;
  Verifier _verifier;
  boost::asio::strand<Executor> _strand;
  boost::asio::steady_timer _timer;
  // On the strand only.
  std::vector<std::unique_ptr<OAuthClient>> _clients;
  std::size_t _next = 0;
  dannan::contract::TimePoint _due{};
  dannan::sched::RetryState _retries;
  bool _running = false;

  mutable dannan::contract::Mutex _mutex;
  std::optional<std::string> _token DANNAN_GUARDED_BY(_mutex);
  Status _status DANNAN_GUARDED_BY(_mutex);
};

}  // namespace lugh::client
