//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/ldap/connection.h"

#include <algorithm>
#include <utility>

#include "dannan/identity/crypto.h"

namespace lugh::ldap {

namespace net = http::net;
namespace ssl = http::ssl;

namespace {

constexpr const char* kNoticeOfDisconnection = "1.3.6.1.4.1.1466.20036";
constexpr std::size_t kReadChunk = 16 * 1024;
constexpr Deadline kBindDeadline = std::chrono::seconds(30);
constexpr Deadline kIdentityDeadline = std::chrono::seconds(15);
// Entries sent in one write, so an abandon read meanwhile is seen in good time.
constexpr std::size_t kEntriesPerWrite = 64;

// The response that goes with a request, for those that have one.
ResponseOp response_to(const Request& request) {
  if (std::holds_alternative<BindRequest>(request)) return ResponseOp::bind;
  if (std::holds_alternative<SearchRequest>(request)) return ResponseOp::search_done;
  if (std::holds_alternative<ModifyRequest>(request)) return ResponseOp::modify;
  if (std::holds_alternative<AddRequest>(request)) return ResponseOp::add;
  if (std::holds_alternative<DeleteRequest>(request)) return ResponseOp::remove;
  if (std::holds_alternative<ModifyDnRequest>(request)) return ResponseOp::modify_dn;
  return ResponseOp::compare;
}

std::string address_of(const net::ip::tcp::socket& socket) {
  boost::system::error_code ec;
  const auto endpoint = socket.remote_endpoint(ec);
  return ec ? std::string() : endpoint.address().to_string();
}

}  // namespace

template <typename Handler>
void Connection::_read_some(Handler handler) {
  const auto space = net::buffer(_buffer.data() + _used, _buffer.size() - _used);
  if (_tls) {
    _stream.async_read_some(space, net::bind_executor(_strand, std::move(handler)));
  } else {
    _stream.next_layer().async_read_some(space, net::bind_executor(_strand, std::move(handler)));
  }
}

template <typename Handler>
void Connection::_write_all(std::shared_ptr<std::string> bytes, Handler handler) {
  if (_tls) {
    net::async_write(_stream, net::buffer(*bytes), net::bind_executor(_strand, std::move(handler)));
  } else {
    net::async_write(_stream.next_layer(), net::buffer(*bytes), net::bind_executor(_strand, std::move(handler)));
  }
}

Connection::Connection(net::ip::tcp::socket socket, ConnectionParts parts, bool start_with_tls)
    : _strand(net::make_strand(socket.get_executor())),
      _stream(std::move(socket), *parts.tls),
      _parts(std::move(parts)),
      _tls(start_with_tls),
      _address(address_of(_stream.next_layer())),
      _timer(_strand),
      _buffer(kMostMessageBytes + kReadChunk) {}

void Connection::start() {
  net::post(_strand, [self = shared_from_this()] {
    if (self->_tls) return self->_handshake();
    self->_arm(self->_parts.idle);
    self->_read();
  });
}

void Connection::close() {
  net::post(_strand, [self = shared_from_this()] { self->_close_now(); });
}

void Connection::_close_now() {
  if (_closing) return;
  _closing = true;
  _timer.cancel();
  boost::system::error_code ignored;
  _stream.next_layer().shutdown(net::ip::tcp::socket::shutdown_both, ignored);
  _stream.next_layer().close(ignored);
  // What was read held passwords, in their turn.
  dannan::identity::cleanse(std::span(_buffer.data(), _buffer.size()));
}

void Connection::_arm(std::chrono::milliseconds after) {
  _timer.expires_after(after);
  _timer.async_wait([self = shared_from_this()](const boost::system::error_code& ec) {
    if (!ec) self->_close_now();
  });
}

void Connection::_handshake() {
  _arm(_parts.handshake);
  _stream.async_handshake(ssl::stream_base::server, net::bind_executor(_strand, [self = shared_from_this()](const boost::system::error_code& ec) {
                            if (ec) return self->_close_now();
                            self->_tls = true;
                            self->_hold_reads = false;
                            self->_arm(self->_parts.idle);
                            self->_read();
                          }));
}

void Connection::_read() {
  if (_reading || _closing || _hold_reads || _queue.size() >= _parts.most_pending) return;
  // Past any whole message, there is always room: a frame longer than the cap is refused by its
  // header, and the buffer is longer than the cap.
  _reading = true;
  _read_some([self = shared_from_this()](const boost::system::error_code& ec, std::size_t bytes) {
    self->_reading = false;
    if (self->_closing) return;
    if (ec) return self->_close_now();
    self->_used += bytes;
    self->_arm(self->_parts.idle);
    self->_take_messages();
    self->_read();
  });
}

void Connection::_take_messages() {
  while (!_closing && !_hold_reads && _queue.size() < _parts.most_pending) {
    const auto framed = ber::frame(ber::Bytes(_buffer.data(), _used), kMostMessageBytes);
    if (framed.state == ber::Frame::State::partial) break;
    if (framed.state == ber::Frame::State::invalid) return _disconnect(ResultCode::protocol_error, "that message is not one Lugh reads");
    auto message = parse_message(ber::Bytes(_buffer.data(), framed.size));
    dannan::identity::cleanse(std::span(_buffer.data(), framed.size));
    std::move(_buffer.begin() + static_cast<std::ptrdiff_t>(framed.size), _buffer.begin() + static_cast<std::ptrdiff_t>(_used), _buffer.begin());
    _used -= framed.size;
    if (!message) return _disconnect(ResultCode::protocol_error, "that message is not one Lugh reads");

    if (const auto* abandon = std::get_if<AbandonRequest>(&message->request)) {
      _abandoned.insert(abandon->id);
      continue;
    }
    if (const auto* extended = std::get_if<ExtendedRequest>(&message->request); extended && extended->oid == kStartTlsOid) {
      // Nothing is read after it until the handshake: what follows in plaintext must not be taken
      // as if it came over TLS.
      _hold_reads = true;
    }
    _queue.push_back({std::move(*message)});
  }
  _next();
}

void Connection::_finished() {
  _busy = false;
  _running.reset();
  // What has been read while this ran, or stopped reading for it.
  _take_messages();
  _read();
}

void Connection::_next() {
  if (_busy || _closing || _queue.empty()) return;
  auto message = std::move(_queue.front().message);
  _queue.pop_front();
  _busy = true;
  _running = message.id;
  _operation(std::move(message));
}

void Connection::_operation(Message message) {
  const auto id = message.id;
  // Abandoned before its turn: no response, as RFC 4511 section 4.11 has it.
  if (_abandoned.erase(id) > 0) return _finished();
  // After what came before it has been answered.
  if (std::holds_alternative<UnbindRequest>(message.request)) return _close_now();

  // Abandon aside, everything counts: one taken here or there is no reason to refuse a caller, but
  // a flood is.
  const auto& limits = _parts.throttle->limits();
  const auto over = _bound ? _parts.throttle->take("ldap-caller:" + _bound->caller.id, limits.caller) : _parts.throttle->take("ldap:" + _address, limits.open);
  if (over) return _refuse(id, message.request, {ResultCode::busy, "", "too many requests: try again in a moment"});

  // A critical control this server does not do is refused; paged results is for a search.
  std::optional<PagedResults> paged;
  std::optional<Filter> assertion;
  const bool is_write = std::holds_alternative<ModifyRequest>(message.request) || std::holds_alternative<AddRequest>(message.request) ||
                        std::holds_alternative<DeleteRequest>(message.request) || std::holds_alternative<ModifyDnRequest>(message.request);
  for (const auto& control : message.controls) {
    const bool is_search = std::holds_alternative<SearchRequest>(message.request);
    if (control.oid == kAssertionOid && is_write) {
      const auto value = control.value.value_or("");
      ber::Reader reader(ber::Bytes(reinterpret_cast<const unsigned char*>(value.data()), value.size()));
      const auto element = reader.next();
      if (element && reader.empty()) assertion = parse_filter(*element);
      if (!assertion) return _refuse(id, message.request, {ResultCode::protocol_error, "", "that assertion control cannot be read"});
      continue;
    }
    if (control.oid == kPagedResultsOid && is_search) {
      paged = control.value ? parse_paged_results(*control.value) : std::nullopt;
      if (!paged) return _refuse(id, message.request, {ResultCode::protocol_error, "", "that paged results control cannot be read"});
    } else if (control.critical) {
      return _refuse(id, message.request, {ResultCode::unavailable_critical_extension, "", "a critical control Lugh does not do"});
    }
  }

  if (auto* bind = std::get_if<BindRequest>(&message.request)) return _bind(id, std::move(*bind));
  if (auto* extended = std::get_if<ExtendedRequest>(&message.request)) return _extended(id, std::move(*extended));

  if (auto* search = std::get_if<SearchRequest>(&message.request)) {
    // Over plaintext, the rootDSE alone.
    const bool root = search->base.empty() && search->scope == Scope::base;
    if (!_tls && !root) return _refuse(id, message.request, {ResultCode::confidentiality_required, "", "StartTLS first"});
    return _with_identity([self = shared_from_this(), id, request = std::move(*search), paged](std::optional<Bound> bound) mutable {
      self->_search(id, std::move(request), paged, std::move(bound));
    });
  }
  if (!_tls) return _refuse(id, message.request, {ResultCode::confidentiality_required, "", "StartTLS first"});
  if (auto* compare = std::get_if<CompareRequest>(&message.request)) {
    return _with_identity([self = shared_from_this(), id, request = std::move(*compare)](std::optional<Bound> bound) mutable {
      self->_compare(id, std::move(request), std::move(bound));
    });
  }
  _write_operation(id, std::move(message.request), std::move(assertion));
}

void Connection::_write_operation(std::int64_t id, Request request, std::optional<Filter> assertion) {
  // Held: a request may hold a Secret, which does not copy.
  auto held = std::make_shared<Request>(std::move(request));
  _with_identity([self = shared_from_this(), id, held, assertion = std::move(assertion)](std::optional<Bound> bound) {
    if (!bound) return self->_refuse(id, *held, {ResultCode::insufficient_access_rights, "", "bind first"});
    Writes::Asking asking{std::move(*bound), self->_address, assertion};
    const auto op = response_to(*held);
    const auto answered = [self, id, op](Result result) { self->_write(encode_result(id, op, result), [self] { self->_finished(); }); };
    if (auto* add = std::get_if<AddRequest>(held.get())) return self->_parts.writes->add(std::move(asking), std::move(*add), self->_strand, answered);
    if (auto* modify = std::get_if<ModifyRequest>(held.get()))
      return self->_parts.writes->modify(std::move(asking), std::move(*modify), self->_strand, answered);
    if (auto* remove = std::get_if<DeleteRequest>(held.get()))
      return self->_parts.writes->remove(std::move(asking), std::move(*remove), self->_strand, answered);
    self->_parts.writes->rename(std::move(asking), std::get<ModifyDnRequest>(std::move(*held)), self->_strand, answered);
  });
}

void Connection::_with_identity(std::function<void(std::optional<Bound>)> then) {
  if (!_bound) return then(std::nullopt);
  auto self = shared_from_this();
  _parts.binder->current(*_bound, kIdentityDeadline, _strand, [self, then = std::move(then)](Outcome<std::optional<Bound>> read) {
    // A store that cannot answer proves nothing either way: this operation runs with no identity,
    // and the bind stands for the next.
    if (!read.ok()) return then(std::nullopt);
    self->_bound = read.value;
    then(read.value);
  });
}

void Connection::_refuse(std::int64_t id, const Request& request, Result result) {
  auto self = shared_from_this();
  const auto bytes = std::holds_alternative<ExtendedRequest>(request) ? encode_extended(id, result) : encode_result(id, response_to(request), result);
  _write(bytes, [self] { self->_finished(); });
}

void Connection::_bind(std::int64_t id, BindRequest request) {
  auto self = shared_from_this();
  const auto answer = [self, id](Result result) { self->_write(encode_result(id, ResponseOp::bind, result), [self] { self->_finished(); }); };
  // RFC 4513 section 3.1.2: whatever comes of a bind, the identity before it is gone.
  _bound.reset();
  if (request.version != 3) return answer({ResultCode::protocol_error, "", "LDAP version 3 only"});
  if (!request.password) return answer({ResultCode::auth_method_not_supported, "", "simple bind only"});
  // Before the TLS check: it carries no credential, and it is how a stock client starts, even to
  // read the rootDSE that tells it StartTLS is there.
  if (_parts.anonymous_bind && request.name.empty() && request.password->reveal().empty()) return answer({});
  if (!_tls) return answer({ResultCode::confidentiality_required, "", "StartTLS first"});
  _parts.binder->bind(std::move(request.name), std::move(*request.password), _address, kBindDeadline, _strand, [self, answer](BindAnswer bound) {
    self->_bound = std::move(bound.bound);
    answer(std::move(bound.result));
  });
}

void Connection::_search(std::int64_t id, SearchRequest request, std::optional<PagedResults> paged, std::optional<Bound> bound) {
  auto self = shared_from_this();
  _parts.operations->search(bound, std::move(request), paged, _strand,
                            [self, id](SearchAnswer answer) { self->_send_entries(id, std::make_shared<SearchAnswer>(std::move(answer)), 0); });
}

void Connection::_send_entries(std::int64_t id, std::shared_ptr<SearchAnswer> answer, std::size_t at) {
  auto self = shared_from_this();
  const auto finished = [self] { self->_finished(); };
  // RFC 4511 section 4.11: abandoned, it stops, and is not answered.
  if (_abandoned.erase(id) > 0) return finished();
  if (at >= answer->entries.size()) {
    std::vector<Control> controls;
    if (answer->paged) controls.push_back({kPagedResultsOid, false, encode_paged_results(*answer->paged)});
    return _write(encode_result(id, ResponseOp::search_done, answer->result, controls), finished);
  }
  std::string bytes;
  const auto end = std::min(at + kEntriesPerWrite, answer->entries.size());
  for (auto i = at; i < end; ++i) bytes += encode_search_entry(id, answer->entries[i].dn, answer->entries[i].attributes);
  _write(std::move(bytes), [self, id, answer, end] { self->_send_entries(id, answer, end); });
}

void Connection::_compare(std::int64_t id, CompareRequest request, std::optional<Bound> bound) {
  auto self = shared_from_this();
  _parts.operations->compare(bound, std::move(request), _strand,
                             [self, id](Result result) { self->_write(encode_result(id, ResponseOp::compare, result), [self] { self->_finished(); }); });
}

void Connection::_extended(std::int64_t id, ExtendedRequest request) {
  auto self = shared_from_this();
  const auto answer = [self, id](Result result, std::optional<std::string> oid, std::optional<std::string> value) {
    self->_write(encode_extended(id, result, oid, value), [self] { self->_finished(); });
  };
  if (request.oid == kStartTlsOid) return _start_tls(id);
  if (!_tls) return answer({ResultCode::confidentiality_required, "", "StartTLS first"}, std::nullopt, std::nullopt);
  if (request.oid == kWhoAmIOid) {
    return _with_identity([answer](std::optional<Bound> bound) { answer({}, std::nullopt, Operations::who_am_i(bound)); });
  }
  if (request.oid == kPasswordModifyOid) {
    auto parsed = parse_password_modify(request.value.value_or(std::string()));
    if (!parsed) return answer({ResultCode::protocol_error, "", "that Password Modify cannot be read"}, std::nullopt, std::nullopt);
    auto held = std::make_shared<PasswordModify>(std::move(*parsed));
    return _with_identity([self, answer, held](std::optional<Bound> bound) {
      if (!bound) return answer({ResultCode::insufficient_access_rights, "", "bind first"}, std::nullopt, std::nullopt);
      Writes::Asking asking{std::move(*bound), self->_address, std::nullopt};
      self->_parts.writes->password_modify(std::move(asking), std::move(*held), self->_strand,
                                           [answer](Result result) { answer(std::move(result), std::nullopt, std::nullopt); });
    });
  }
  answer({ResultCode::protocol_error, "", "an extended operation Lugh does not do"}, std::nullopt, std::nullopt);
}

void Connection::_start_tls(std::int64_t id) {
  auto self = shared_from_this();
  const auto refuse = [self, id](const std::string& why) {
    self->_hold_reads = false;
    self->_write(encode_extended(id, {ResultCode::operations_error, "", why}, std::string(kStartTlsOid)), [self] { self->_finished(); });
  };
  if (_tls) return refuse("TLS is already up");
  // Anything sent after the request and before the handshake is not what TLS will protect: it is
  // a command injected on the way, so it ends the connection rather than being acted on.
  if (_used != 0) return _disconnect(ResultCode::protocol_error, "nothing may follow StartTLS until the handshake");
  _write(encode_extended(id, {}, std::string(kStartTlsOid)), [self] {
    if (self->_used != 0) return self->_close_now();
    self->_busy = false;
    self->_running.reset();
    self->_handshake();
  });
}

void Connection::_write(std::string bytes, std::function<void()> then) {
  if (_closing) return;
  auto held = std::make_shared<std::string>(std::move(bytes));
  _arm(_parts.write);
  _write_all(held, [self = shared_from_this(), held, then = std::move(then)](const boost::system::error_code& ec, std::size_t) {
    if (ec) return self->_close_now();
    self->_arm(self->_parts.idle);
    then();
  });
}

void Connection::_disconnect(ResultCode code, const std::string& why) {
  _hold_reads = true;
  _queue.clear();
  auto self = shared_from_this();
  // A write may already be going out: the notice is best effort, and the connection closes.
  if (_busy) return _close_now();
  _busy = true;
  _write(encode_extended(0, {code, "", why}, std::string(kNoticeOfDisconnection)), [self] { self->_close_now(); });
}

}  // namespace lugh::ldap
