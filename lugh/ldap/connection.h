//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <cstddef>
#include <deque>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "lugh/http/http_types.h"
#include "lugh/http/rate_limiter.h"
#include "lugh/ldap/authz.h"
#include "lugh/ldap/messages.h"
#include "lugh/ldap/operations.h"
#include "lugh/ldap/writes.h"

namespace lugh::ldap {

// What one connection needs, shared by all of them.
struct ConnectionParts {
  std::shared_ptr<Binder> binder;
  std::shared_ptr<Operations> operations;
  std::shared_ptr<Writes> writes;
  std::shared_ptr<http::ssl::context> tls;
  // The HTTP routes' limits: by address until bound, by caller after.
  std::shared_ptr<http::Throttle> throttle;
  // Operations queued before the connection stops reading (`ldap.most_pending`).
  std::size_t most_pending = 8;
  // A connection with nothing happening closes after this (`ldap.idle`): SSSD and mail servers hold
  // one open between lookups.
  std::chrono::milliseconds idle = std::chrono::minutes(10);
  std::chrono::milliseconds handshake = std::chrono::seconds(10);
  std::chrono::milliseconds write = std::chrono::seconds(30);
};

// One client. Messages are read as they come and answered strictly in turn, one operation at a
// time, so a bind cannot overtake what came before it. Everything happens on the connection's own
// strand. Abandon and unbind act as soon as they are read. What cannot be read as a message is
// answered with a Notice of Disconnection (RFC 4511 section 4.4.1) and the connection closes.
class Connection : public std::enable_shared_from_this<Connection> {
 public:
  // `start_with_tls` for an LDAPS listener; otherwise plaintext until StartTLS, which carries
  // nothing but StartTLS and the rootDSE.
  Connection(http::net::ip::tcp::socket socket, ConnectionParts parts, bool start_with_tls);

  void start();

  // Closes it, from any thread.
  void close();

 private:
  struct Queued {
    Message message;
  };

  void _handshake();
  void _read();
  void _take_messages();
  void _next();
  void _finished();
  void _operation(Message message);
  void _bind(std::int64_t id, BindRequest request);
  void _search(std::int64_t id, SearchRequest request, std::optional<PagedResults> paged, std::optional<Bound> bound);
  void _send_entries(std::int64_t id, std::shared_ptr<SearchAnswer> answer, std::size_t at);
  void _compare(std::int64_t id, CompareRequest request, std::optional<Bound> bound);
  void _extended(std::int64_t id, ExtendedRequest request);
  void _start_tls(std::int64_t id);
  void _write_operation(std::int64_t id, Request request, std::optional<Filter> assertion);
  // With the identity as it stands now: anonymous if it no longer holds.
  void _with_identity(std::function<void(std::optional<Bound>)> then);
  void _refuse(std::int64_t id, const Request& request, Result result);
  void _write(std::string bytes, std::function<void()> then);
  void _disconnect(ResultCode code, const std::string& why);
  void _close_now();
  void _arm(std::chrono::milliseconds after);
  template <typename Handler>
  void _read_some(Handler handler);
  template <typename Handler>
  void _write_all(std::shared_ptr<std::string> bytes, Handler handler);

  http::net::strand<http::net::any_io_executor> _strand;
  http::ssl::stream<http::net::ip::tcp::socket> _stream;
  ConnectionParts _parts;
  bool _tls = false;
  std::string _address;
  http::net::steady_timer _timer;

  std::vector<unsigned char> _buffer;
  std::size_t _used = 0;
  bool _reading = false;
  // A StartTLS has been read: nothing more is, until the handshake is over.
  bool _hold_reads = false;
  bool _closing = false;
  bool _busy = false;
  std::deque<Queued> _queue;
  std::set<std::int64_t> _abandoned;
  std::optional<std::int64_t> _running;
  std::optional<Bound> _bound;
};

}  // namespace lugh::ldap
