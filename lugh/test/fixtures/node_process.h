//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/json.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

#include "dannan/test/fixtures/child_process.h"
#include "dannan/test/fixtures/ports.h"
#include "lugh/test/fixtures/temp_directory.h"
#include "lugh/test/fixtures/test_certificate.h"

#ifndef LUGH_NODE_BINARY
#error "LUGH_NODE_BINARY must name the lugh-node the process tests run"
#endif

// The real lugh-node, run as systemd would run it, for the tests that only a whole process
// shows: init and genesis, starting with and without what init made, the API through TLS,
// and stopping on a signal. Every wait has a deadline.
namespace node_process {

using Clock = std::chrono::steady_clock;

inline const std::string kBinary = LUGH_NODE_BINARY;
inline constexpr const char* kCredential = "lugh-master-key";

inline std::string read_file(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  std::stringstream text;
  text << in.rdbuf();
  return text.str();
}

inline void write_file(const std::filesystem::path& path, const std::string& content) { std::ofstream(path, std::ios::binary | std::ios::trunc) << content; }

// Whether any file under `directory` holds `needle`.
inline bool on_disk(const std::filesystem::path& directory, const std::string& needle) {
  if (!std::filesystem::exists(directory)) return false;
  for (const auto& entry : std::filesystem::recursive_directory_iterator(directory)) {
    if (entry.is_regular_file() && read_file(entry.path()).find(needle) != std::string::npos) return true;
  }
  return false;
}

// An empty configuration of the test's own, so a node under test never reads the host's
// installed one (/usr/local/etc/lugh/config.yaml), which a host running Lugh has and its
// service alone may read (found on the build nodes, 2026-11-16). A test's own --config wins over it.
inline std::filesystem::path empty_config() {
  static const auto path = [] {
    const auto made = std::filesystem::path(DANNAN_TEST_TEMP_ROOT) / "lugh-empty-config.yaml";
    std::filesystem::create_directories(made.parent_path());
    std::ofstream(made, std::ios::binary | std::ios::trunc) << "# Nothing: the defaults and the command line.\n";
    return made;
  }();
  return path;
}

// This process's environment without anything that would configure Lugh, so the test says
// what the node sees; with CREDENTIALS_DIRECTORY when there are credentials.
inline std::vector<std::string> environment(const std::optional<std::filesystem::path>& credentials = std::nullopt) {
  std::vector<std::string> out;
  for (char** entry = environ; *entry != nullptr; ++entry) {
    const std::string variable(*entry);
    if (variable.rfind("LUGH_", 0) == 0 || variable.rfind("CREDENTIALS_DIRECTORY=", 0) == 0) continue;
    out.push_back(variable);
  }
  out.push_back("LUGH_CONFIG=" + empty_config().string());
  if (credentials) out.push_back("CREDENTIALS_DIRECTORY=" + credentials->string());
  return out;
}

// A directory of the test's own, with a certificate pair for the server.
struct Workspace {
  TempDirectory dir;
  std::filesystem::path certificate = dir.path() / "cert.pem";
  std::filesystem::path key = dir.path() / "key.pem";

  Workspace() {
    const TestCertificate pair;
    write_file(certificate, pair.certificate_pem);
    write_file(key, pair.key_pem);
  }

  std::filesystem::path path(const std::string& name) const { return dir.path() / name; }
};

// What a command that runs to its end said, and how it ended.
struct Ran {
  int status = -1;
  std::string out;
  std::string err;
};

// `lugh-node <args>` to its end, its standard output read raw (a master key is 32 bytes of
// anything), and its standard error from the log.
inline Ran run(const Workspace& workspace, std::vector<std::string> args, dannan::test::ChildOptions options = {}) {
  static int sequence = 0;
  const auto log = workspace.path("run-" + std::to_string(++sequence) + ".log");
  if (!options.environment) options.environment = environment();
  args.insert(args.begin(), kBinary);
  dannan::test::ChildProcess child(args, log, options);
  const auto deadline = Clock::now() + std::chrono::seconds(60);
  Ran ran;
  ran.out = child.read_all(deadline);
  ran.status = child.wait(deadline).value_or(-1);
  ran.err = read_file(log);
  return ran;
}

// `lugh-node init` for a state directory, with any further arguments.
inline Ran init(const Workspace& workspace, const std::filesystem::path& state, std::vector<std::string> extra = {},
                std::optional<std::string> input = std::nullopt) {
  std::vector<std::string> args{"init", "--state-directory", state.string()};
  args.insert(args.end(), extra.begin(), extra.end());
  return run(workspace, args, {.environment = environment(), .input = std::move(input)});
}

// The password genesis showed on standard error: the indented line two after its label.
inline std::string root_password(const std::string& err) {
  std::istringstream lines(err);
  std::vector<std::string> all;
  for (std::string line; std::getline(lines, line);) all.push_back(line);
  for (std::size_t i = 0; i + 2 < all.size(); ++i) {
    if (all[i].rfind("The root password", 0) == 0) {
      auto password = all[i + 2];
      password.erase(0, password.find_first_not_of(" \t"));
      password.erase(password.find_last_not_of(" \t\r") + 1);
      return password;
    }
  }
  return "";
}

// One HTTPS request to the node on 127.0.0.1, its certificate not checked (this is about
// the service, not the chain), within the deadline; nothing if no answer came.
struct Answer {
  unsigned status = 0;
  std::string body;
  std::string www_authenticate;
  boost::json::value json() const { return body.empty() ? boost::json::value() : boost::json::parse(body); }
};

inline std::optional<Answer> request(std::uint16_t port, boost::beast::http::verb method, const std::string& target,
                                     const std::optional<std::string>& authorization = std::nullopt, const std::optional<std::string>& body = std::nullopt,
                                     std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
  namespace net = boost::asio;
  namespace beast = boost::beast;
  namespace http = boost::beast::http;

  net::io_context io;
  net::ssl::context context(net::ssl::context::tls_client);
  context.set_verify_mode(net::ssl::verify_none);
  beast::ssl_stream<beast::tcp_stream> stream(io, context);

  http::request<http::string_body> out{method, target, 11};
  out.set(http::field::host, "127.0.0.1");
  if (authorization) out.set(http::field::authorization, *authorization);
  if (body) {
    out.set(http::field::content_type, "application/json");
    out.body() = *body;
  }
  out.prepare_payload();

  beast::flat_buffer buffer;
  http::response<http::string_body> in;
  bool answered = false;
  const net::ip::tcp::endpoint where(net::ip::make_address("127.0.0.1"), port);
  stream.next_layer().async_connect(where, [&](beast::error_code connected) {
    if (connected) return;
    stream.async_handshake(net::ssl::stream_base::client, [&](beast::error_code shaken) {
      if (shaken) return;
      http::async_write(stream, out, [&](beast::error_code written, std::size_t) {
        if (written) return;
        http::async_read(stream, buffer, in, [&](beast::error_code read, std::size_t) { answered = !read; });
      });
    });
  });
  io.run_for(timeout);
  if (!answered) return std::nullopt;

  Answer answer;
  answer.status = in.result_int();
  answer.body = in.body();
  if (const auto found = in.find(http::field::www_authenticate); found != in.end()) answer.www_authenticate = std::string(found->value());
  return answer;
}

// One HTTPS request with any headers and body, and every header of the answer, for what a
// browser does: forms, cookies, redirects not followed.
struct Reply {
  unsigned status = 0;
  std::string body;
  std::vector<std::pair<std::string, std::string>> headers;

  std::string header(const std::string& name) const {
    for (const auto& [key, value] : headers) {
      if (boost::beast::iequals(key, name)) return value;
    }
    return {};
  }
  std::vector<std::string> all(const std::string& name) const {
    std::vector<std::string> out;
    for (const auto& [key, value] : headers) {
      if (boost::beast::iequals(key, name)) out.push_back(value);
    }
    return out;
  }
};

inline std::optional<Reply> send(std::uint16_t port, boost::beast::http::verb method, const std::string& target,
                                 const std::vector<std::pair<std::string, std::string>>& headers = {}, const std::string& body = "",
                                 std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
  namespace net = boost::asio;
  namespace beast = boost::beast;
  namespace http = boost::beast::http;

  net::io_context io;
  net::ssl::context context(net::ssl::context::tls_client);
  context.set_verify_mode(net::ssl::verify_none);
  beast::ssl_stream<beast::tcp_stream> stream(io, context);

  http::request<http::string_body> out{method, target, 11};
  out.set(http::field::host, "127.0.0.1");
  for (const auto& [name, value] : headers) out.set(name, value);
  out.body() = body;
  out.prepare_payload();

  beast::flat_buffer buffer;
  http::response<http::string_body> in;
  bool answered = false;
  const net::ip::tcp::endpoint where(net::ip::make_address("127.0.0.1"), port);
  stream.next_layer().async_connect(where, [&](beast::error_code connected) {
    if (connected) return;
    stream.async_handshake(net::ssl::stream_base::client, [&](beast::error_code shaken) {
      if (shaken) return;
      http::async_write(stream, out, [&](beast::error_code written, std::size_t) {
        if (written) return;
        http::async_read(stream, buffer, in, [&](beast::error_code read, std::size_t) { answered = !read; });
      });
    });
  });
  io.run_for(timeout);
  if (!answered) return std::nullopt;

  Reply reply;
  reply.status = in.result_int();
  reply.body = in.body();
  for (const auto& field : in.base()) reply.headers.emplace_back(std::string(field.name_string()), std::string(field.value()));
  return reply;
}

// Polls /health until it answers {"status":"ok"}, the child exits, or the deadline passes.
inline bool wait_until_up(dannan::test::ChildProcess& child, std::uint16_t port, std::chrono::seconds within) {
  const auto deadline = Clock::now() + within;
  while (Clock::now() < deadline) {
    if (child.wait(Clock::now())) return false;
    if (const auto health = request(port, boost::beast::http::verb::get, "/health", std::nullopt, std::nullopt, std::chrono::milliseconds(500))) {
      return health->status == 200 && health->json() == boost::json::value{{"status", "ok"}};
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
  }
  return false;
}

// The service, started on a free port with the workspace's certificate and the given state
// and credentials, stopped (SIGTERM) when it goes.
class Serving {
 public:
  // `port`, when given, is the one to listen on: for a configuration that must name it first
  // (an issuer's URL).
  Serving(const Workspace& workspace, const std::filesystem::path& state, std::optional<std::filesystem::path> credentials,
          std::optional<std::string> input = std::nullopt, const std::vector<std::string>& arguments = {}, std::optional<std::uint16_t> port = std::nullopt)
      : _log(workspace.path("serve-" + std::to_string(++_sequence) + ".log")),
        _port(port.value_or(dannan::test::free_port())),
        _child(command_line(workspace, state, _port, arguments), _log, {.environment = environment(credentials), .input = std::move(input)}) {}

  // Whether it came up, within 15 seconds.
  bool up() { return wait_until_up(_child, _port, std::chrono::seconds(15)); }

  std::uint16_t port() const { return _port; }
  dannan::test::ChildProcess& child() { return _child; }

  // Stops it, if it is running, and answers its log.
  std::string stop() {
    _child.terminate();
    if (!_child.wait(Clock::now() + std::chrono::seconds(5))) {
      _child.signal(SIGKILL);
      _child.wait(Clock::now() + std::chrono::seconds(5));
    }
    return log();
  }

  std::string log() const { return read_file(_log); }

 private:
  static std::vector<std::string> command_line(const Workspace& workspace, const std::filesystem::path& state, std::uint16_t port,
                                               const std::vector<std::string>& arguments) {
    std::vector<std::string> out{kBinary,         "--tls-certificate",    workspace.certificate.string(),
                                 "--tls-key",     workspace.key.string(), "--state-directory",
                                 state.string(),  "--server-address",     "127.0.0.1",
                                 "--server-port", std::to_string(port)};
    out.insert(out.end(), arguments.begin(), arguments.end());
    return out;
  }

  static inline int _sequence = 0;
  std::filesystem::path _log;
  std::uint16_t _port;
  dannan::test::ChildProcess _child;
};

// A node made with `lugh-node init`, its master key where systemd would put the credential.
struct Initialised {
  std::filesystem::path state;
  std::filesystem::path credentials;
  Ran made;

  explicit Initialised(const Workspace& workspace) : state(workspace.path("state")), credentials(workspace.path("credentials")) {
    std::filesystem::create_directories(credentials);
    std::filesystem::permissions(credentials, std::filesystem::perms::owner_all);
    made = init(workspace, state);
    write_file(credentials / kCredential, made.out);
  }
};

}  // namespace node_process
