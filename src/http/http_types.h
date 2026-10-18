#pragma once

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <functional>
#include <memory>
#include <string>

namespace lugh::http {

namespace beast = boost::beast;
namespace net = boost::asio;
namespace ssl = boost::asio::ssl;

// Beast's HTTP vocabulary, brought into this namespace, so a route says http::verb::get and
// http::status::ok and means ours and Beast's at once.
using verb = beast::http::verb;
using status = beast::http::status;
using field = beast::http::field;
using error = beast::http::error;
using beast::http::to_string;

using HttpRequest = beast::http::request<beast::http::string_body>;
using HttpResponse = beast::http::response<beast::http::string_body>;

// The request, the client's address, the response to fill, and next: next(true) continues
// the chain, next(false) stops it and sends the response. Either may be called from any
// thread, once. The address is the client's as ClientAddress decided it, not necessarily
// the socket's peer.
using HttpMiddleware = std::function<void(const HttpRequest&, const std::string&, std::shared_ptr<HttpResponse>, std::function<void(bool)>)>;

}  // namespace lugh::http
