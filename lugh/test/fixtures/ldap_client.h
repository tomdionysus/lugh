//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "lugh/ldap/ber.h"
#include "lugh/ldap/messages.h"

// A small LDAP client over real sockets and the same BER, for the connection and process tests:
// LDAPS, or plaintext with StartTLS. The certificate is not checked, since this is about LDAP and
// not about the chain. Every read has a deadline, and a connection that closes is an answer.
namespace ldap_client {

namespace net = boost::asio;
namespace ber = lugh::ldap::ber;
using tcp = net::ip::tcp;

struct Response {
  std::int64_t id = 0;
  std::uint8_t op = 0;
  int code = -1;
  std::string message;
  // A search entry's.
  std::string dn;
  std::map<std::string, std::vector<std::string>> attributes;
  // An extended response's.
  std::string oid;
  std::string value;
  // The paged results control's cookie, on a search done that has one.
  std::optional<std::string> cookie;
};

inline constexpr std::uint8_t kBindResponse = 0x61;
inline constexpr std::uint8_t kSearchEntry = 0x64;
inline constexpr std::uint8_t kSearchDone = 0x65;
inline constexpr std::uint8_t kExtendedResponse = 0x78;
inline constexpr std::uint8_t kCompareResponse = 0x6F;

class Client {
 public:
  enum class Mode { ldaps, plaintext };

  Client(std::uint16_t port, Mode mode, std::chrono::milliseconds timeout = std::chrono::seconds(10)) : _tls(net::ssl::context::tls_client), _timeout(timeout) {
    _tls.set_verify_mode(net::ssl::verify_none);
    _stream = std::make_unique<net::ssl::stream<tcp::socket>>(_io, _tls);
    boost::system::error_code ec;
    _stream->next_layer().connect(tcp::endpoint(net::ip::make_address("127.0.0.1"), port), ec);
    connected = !ec;
    if (connected && mode == Mode::ldaps) connected = handshake();
  }

  bool connected = false;

  bool handshake() {
    bool done = false;
    bool ok = false;
    _stream->async_handshake(net::ssl::stream_base::client, [&](const boost::system::error_code& ec) {
      done = true;
      ok = !ec;
    });
    _run_until(done);
    _secure = ok;
    return ok;
  }

  std::int64_t next_id() { return _next++; }

  // Sends bytes as they are.
  bool send_raw(const std::string& bytes) {
    bool done = false;
    bool ok = false;
    const auto handler = [&](const boost::system::error_code& ec, std::size_t) {
      done = true;
      ok = !ec;
    };
    if (_secure) {
      net::async_write(*_stream, net::buffer(bytes), handler);
    } else {
      net::async_write(_stream->next_layer(), net::buffer(bytes), handler);
    }
    _run_until(done);
    return ok;
  }

  // The next response, or nothing if the connection closed or the time ran out.
  std::optional<Response> read() {
    for (;;) {
      const auto framed = ber::frame(ber::Bytes(reinterpret_cast<const unsigned char*>(_held.data()), _held.size()), 16 * 1024 * 1024);
      if (framed.state == ber::Frame::State::complete) {
        const auto bytes = _held.substr(0, framed.size);
        _held.erase(0, framed.size);
        return parse(bytes);
      }
      if (framed.state == ber::Frame::State::invalid || closed) return std::nullopt;
      if (!_fill()) return std::nullopt;
    }
  }

  // Whether the far side has closed, within the timeout, with nothing more to read.
  bool closes() {
    for (;;) {
      if (!_held.empty()) _held.clear();
      if (closed) return true;
      if (!_fill() && !closed) return false;
    }
  }

  std::string bind_bytes(std::int64_t id, const std::string& name, const std::string& password) {
    ber::Writer writer;
    writer.begin(ber::kSequence);
    writer.integer(ber::kInteger, id);
    writer.begin(0x60);
    writer.integer(ber::kInteger, 3);
    writer.octets(ber::kOctetString, name);
    writer.octets(0x80, password);
    writer.end();
    writer.end();
    return writer.bytes();
  }

  std::optional<Response> bind(const std::string& name, const std::string& password) {
    send_raw(bind_bytes(next_id(), name, password));
    return read();
  }

  // A search with a presence filter on objectClass, or the encoded filter given.
  std::string search_bytes(std::int64_t id, const std::string& base, int scope, const std::vector<std::string>& attributes = {},
                           const std::string& filter = std::string("\x87\x0bobjectClass", 13),
                           const std::optional<std::pair<int, std::string>>& paged = std::nullopt) {
    ber::Writer writer;
    writer.begin(ber::kSequence);
    writer.integer(ber::kInteger, id);
    writer.begin(0x63);
    writer.octets(ber::kOctetString, base);
    writer.integer(ber::kEnumerated, scope);
    writer.integer(ber::kEnumerated, 0);
    writer.integer(ber::kInteger, 0);
    writer.integer(ber::kInteger, 0);
    writer.boolean(ber::kBoolean, false);
    writer.raw(filter);
    writer.begin(ber::kSequence);
    for (const auto& one : attributes) writer.octets(ber::kOctetString, one);
    writer.end();
    writer.end();
    if (paged) {
      writer.begin(0xA0);
      writer.begin(ber::kSequence);
      writer.octets(ber::kOctetString, lugh::ldap::kPagedResultsOid);
      writer.octets(ber::kOctetString, lugh::ldap::encode_paged_results({paged->first, paged->second}));
      writer.end();
      writer.end();
    }
    writer.end();
    return writer.bytes();
  }

  // Entries, and the done that ended them; nothing if it never came.
  struct Searched {
    std::vector<Response> entries;
    Response done;
  };
  std::optional<Searched> search(const std::string& base, int scope, const std::vector<std::string>& attributes = {},
                                 const std::string& filter = std::string("\x87\x0bobjectClass", 13),
                                 const std::optional<std::pair<int, std::string>>& paged = std::nullopt) {
    send_raw(search_bytes(next_id(), base, scope, attributes, filter, paged));
    Searched out;
    for (;;) {
      auto response = read();
      if (!response) return std::nullopt;
      if (response->op == kSearchDone) {
        out.done = std::move(*response);
        return out;
      }
      out.entries.push_back(std::move(*response));
    }
  }

  // With `critical_control`, a critical control of that OID on it.
  std::string extended_bytes(std::int64_t id, const std::string& oid, const std::optional<std::string>& value = std::nullopt,
                             const std::string& critical_control = "") {
    ber::Writer writer;
    writer.begin(ber::kSequence);
    writer.integer(ber::kInteger, id);
    writer.begin(0x77);
    writer.octets(0x80, oid);
    if (value) writer.octets(0x81, *value);
    writer.end();
    if (!critical_control.empty()) {
      writer.begin(0xA0);
      writer.begin(ber::kSequence);
      writer.octets(ber::kOctetString, critical_control);
      writer.boolean(ber::kBoolean, true);
      writer.end();
      writer.end();
    }
    writer.end();
    return writer.bytes();
  }

  std::optional<Response> extended(const std::string& oid, const std::optional<std::string>& value = std::nullopt) {
    send_raw(extended_bytes(next_id(), oid, value));
    return read();
  }

  // StartTLS, then the handshake: whether TLS is up.
  bool start_tls() {
    const auto answer = extended(lugh::ldap::kStartTlsOid);
    if (!answer || answer->code != 0) return false;
    return handshake();
  }

  std::optional<Response> compare(const std::string& entry, const std::string& attribute, const std::string& value) {
    ber::Writer writer;
    writer.begin(ber::kSequence);
    writer.integer(ber::kInteger, next_id());
    writer.begin(0x6E);
    writer.octets(ber::kOctetString, entry);
    writer.begin(ber::kSequence);
    writer.octets(ber::kOctetString, attribute);
    writer.octets(ber::kOctetString, value);
    writer.end();
    writer.end();
    writer.end();
    send_raw(writer.bytes());
    return read();
  }

  std::string abandon_bytes(std::int64_t id, std::int64_t target) {
    ber::Writer writer;
    writer.begin(ber::kSequence);
    writer.integer(ber::kInteger, id);
    writer.integer(0x50, target);
    writer.end();
    return writer.bytes();
  }

  std::string unbind_bytes(std::int64_t id) {
    ber::Writer writer;
    writer.begin(ber::kSequence);
    writer.integer(ber::kInteger, id);
    writer.octets(0x42, "");
    writer.end();
    return writer.bytes();
  }

  bool closed = false;

 private:
  void _run_until(bool& done) {
    _io.restart();
    net::steady_timer timer(_io);
    bool timed_out = false;
    timer.expires_after(_timeout);
    timer.async_wait([&](const boost::system::error_code& ec) {
      if (!ec) timed_out = true;
    });
    while (!done && !timed_out) _io.run_one();
    if (!done) {
      boost::system::error_code ignored;
      _stream->next_layer().cancel(ignored);
      _io.restart();
      while (!done) _io.run_one();
    }
    timer.cancel();
    _io.poll();
  }

  bool _fill() {
    char chunk[16 * 1024];
    bool done = false;
    std::size_t got = 0;
    boost::system::error_code result;
    const auto handler = [&](const boost::system::error_code& ec, std::size_t bytes) {
      done = true;
      got = bytes;
      result = ec;
    };
    if (_secure) {
      _stream->async_read_some(net::buffer(chunk), handler);
    } else {
      _stream->next_layer().async_read_some(net::buffer(chunk), handler);
    }
    _run_until(done);
    if (got > 0) _held.append(chunk, got);
    if (result == net::error::operation_aborted) return false;
    if (result) closed = true;
    return !result;
  }

  static std::optional<Response> parse(const std::string& bytes) {
    ber::Reader outer(ber::Bytes(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size()));
    const auto message = outer.next();
    if (!message) return std::nullopt;
    ber::Reader reader(message->content);
    const auto id = reader.next();
    const auto operation = reader.next();
    if (!id || !operation) return std::nullopt;
    Response out;
    out.id = *ber::integer(*id);
    out.op = operation->tag;
    ber::Reader body(operation->content);
    if (out.op == kSearchEntry) {
      out.dn = std::string(body.next()->text());
      const auto attributes = body.next();
      ber::Reader each(attributes->content);
      while (!each.empty()) {
        const auto attribute = each.next();
        ber::Reader parts(attribute->content);
        const auto type = std::string(parts.next()->text());
        ber::Reader values(parts.next()->content);
        auto& kept = out.attributes[type];
        while (!values.empty()) kept.emplace_back(values.next()->text());
      }
      return out;
    }
    out.code = static_cast<int>(*ber::integer(*body.next()));
    body.next();
    out.message = std::string(body.next()->text());
    while (!body.empty()) {
      const auto part = body.next();
      if (part->tag == 0x8A) out.oid = std::string(part->text());
      if (part->tag == 0x8B) out.value = std::string(part->text());
    }
    if (!reader.empty()) {
      const auto controls = reader.next();
      ber::Reader each(controls->content);
      while (!each.empty()) {
        const auto control = each.next();
        ber::Reader parts(control->content);
        const auto oid = std::string(parts.next()->text());
        if (oid == lugh::ldap::kPagedResultsOid) {
          const auto value = parts.next();
          const auto paged = lugh::ldap::parse_paged_results(value->text());
          if (paged) out.cookie = paged->cookie;
        }
      }
    }
    return out;
  }

  net::io_context _io;
  net::ssl::context _tls;
  std::unique_ptr<net::ssl::stream<tcp::socket>> _stream;
  std::chrono::milliseconds _timeout;
  bool _secure = false;
  std::int64_t _next = 1;
  std::string _held;
};

// A presence filter, encoded.
inline std::string filter_present(const std::string& attribute) {
  ber::Writer writer;
  writer.octets(0x87, attribute);
  return writer.bytes();
}

// An equality filter, encoded.
inline std::string filter_equal(const std::string& attribute, const std::string& value) {
  ber::Writer writer;
  writer.begin(0xA3);
  writer.octets(ber::kOctetString, attribute);
  writer.octets(ber::kOctetString, value);
  writer.end();
  return writer.bytes();
}

}  // namespace ldap_client
