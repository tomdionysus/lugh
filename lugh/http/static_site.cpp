//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#include "lugh/http/static_site.h"

#include <fstream>
#include <sstream>
#include <stdexcept>

#include "dannan/identity/crypto.h"
#include "lugh/core/encoding.h"
#include "lugh/http/api_json.h"

namespace lugh::http {

namespace {

std::span<const unsigned char> bytes_of(std::string_view text) { return {reinterpret_cast<const unsigned char*>(text.data()), text.size()}; }

std::string type_of(const std::string& path) {
  static const std::map<std::string, std::string> kTypes = {
      {".html", "text/html; charset=utf-8"},
      {".js", "text/javascript; charset=utf-8"},
      {".mjs", "text/javascript; charset=utf-8"},
      {".css", "text/css; charset=utf-8"},
      {".json", "application/json"},
      {".map", "application/json"},
      {".svg", "image/svg+xml"},
      {".png", "image/png"},
      {".jpg", "image/jpeg"},
      {".ico", "image/x-icon"},
      {".webp", "image/webp"},
      {".woff2", "font/woff2"},
      {".woff", "font/woff"},
      {".txt", "text/plain; charset=utf-8"},
      {".webmanifest", "application/manifest+json"},
  };
  const auto dot = path.rfind('.');
  const auto slash = path.rfind('/');
  if (dot == std::string::npos || (slash != std::string::npos && dot < slash)) return "application/octet-stream";
  const auto found = kTypes.find(path.substr(dot));
  return found == kTypes.end() ? "application/octet-stream" : found->second;
}

bool is_html(const std::string& path) { return path.size() >= 5 && path.compare(path.size() - 5, 5, ".html") == 0; }

// The request's path, without its query, and without the leading '/'.
std::string path_of(const HttpRequest& request) {
  std::string target(request.target());
  const auto query = target.find_first_of("?#");
  if (query != std::string::npos) target.resize(query);
  return target.empty() ? std::string() : target.substr(1);
}

// Whether the last segment names a file: a route of the SPA never has an extension.
bool names_a_file(const std::string& path) {
  const auto slash = path.rfind('/');
  const auto last = slash == std::string::npos ? path : path.substr(slash + 1);
  return last.find('.') != std::string::npos;
}

void serve(const StaticSite::File& file, const HttpRequest& request, HttpResponse& response, bool immutable) {
  response.set(field::content_type, file.type);
  response.set(field::etag, file.etag);
  response.set(field::cache_control, immutable ? "public, max-age=31536000, immutable" : "no-cache");
  response.set("X-Content-Type-Options", "nosniff");
  response.set("Referrer-Policy", "no-referrer");
  if (!file.policy.empty()) {
    response.set("Content-Security-Policy", file.policy);
    response.set("X-Frame-Options", "DENY");
  }
  if (request[field::if_none_match] == file.etag) {
    response.result(status::not_modified);
    response.body().clear();
    return;
  }
  response.result(status::ok);
  if (request.method() == verb::head) {
    response.content_length(file.body.size());
    return;
  }
  response.body() = file.body;
  response.prepare_payload();
}

}  // namespace

StaticSite::StaticSite(Files files) {
  if (!files.count("index.html")) throw std::invalid_argument("the dashboard has no index.html");
  auto held = std::make_shared<std::map<std::string, File>>();
  for (auto& [path, body] : files) {
    File file;
    file.type = type_of(path);
    file.etag = "\"" + encoding::hex(dannan::identity::sha256(bytes_of(body)).bytes).substr(0, 32) + "\"";
    if (is_html(path)) file.policy = page_policy(body);
    file.body = std::move(body);
    held->emplace(path, std::move(file));
  }
  _held = std::move(held);
}

std::string StaticSite::page_policy(const std::string& html) {
  // Each <script> without a src: React Router's SPA page carries its context inline.
  std::string hashes;
  for (std::size_t at = html.find("<script"); at != std::string::npos; at = html.find("<script", at + 1)) {
    const auto open_end = html.find('>', at);
    if (open_end == std::string::npos) break;
    const auto opening = html.substr(at, open_end - at);
    const auto close = html.find("</script>", open_end);
    if (close == std::string::npos) break;
    if (opening.find(" src=") != std::string::npos) continue;
    const auto content = html.substr(open_end + 1, close - open_end - 1);
    hashes += " 'sha256-" + encoding::base64(dannan::identity::sha256(bytes_of(content)).bytes) + "'";
  }
  return "default-src 'self'; script-src 'self'" + hashes +
         "; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; "
         "frame-ancestors 'none'";
}

StaticSite::Files StaticSite::read(const std::filesystem::path& directory, Limits limits) {
  namespace fs = std::filesystem;
  std::error_code ec;
  if (!fs::is_directory(directory, ec)) throw std::runtime_error("the dashboard directory " + directory.string() + " cannot be read");
  Files out;
  std::size_t total = 0;
  fs::recursive_directory_iterator it(directory, fs::directory_options::none, ec);
  if (ec) throw std::runtime_error("the dashboard directory " + directory.string() + " cannot be read: " + ec.message());
  for (const fs::recursive_directory_iterator end; it != end; it.increment(ec)) {
    if (ec) throw std::runtime_error("the dashboard directory " + directory.string() + " cannot be read: " + ec.message());
    const auto& entry = *it;
    const auto name = entry.path().filename().string();
    const bool hidden = !name.empty() && name.front() == '.';
    if (hidden || entry.is_symlink(ec)) {
      if (entry.is_directory(ec)) it.disable_recursion_pending();
      continue;
    }
    if (!entry.is_regular_file(ec)) continue;
    const auto relative = entry.path().lexically_relative(directory).generic_string();
    std::ifstream in(entry.path(), std::ios::binary);
    if (!in) throw std::runtime_error("cannot read " + entry.path().string());
    std::ostringstream body;
    body << in.rdbuf();
    total += body.str().size();
    if (out.size() + 1 > limits.most_files || total > limits.most_bytes)
      throw std::runtime_error("the dashboard directory " + directory.string() + " holds more than the limit of " + std::to_string(limits.most_files) +
                               " files or " + std::to_string(limits.most_bytes) + " bytes");
    out.emplace(relative, body.str());
  }
  if (!out.count("index.html")) throw std::runtime_error("the dashboard directory " + directory.string() + " has no index.html");
  return out;
}

HttpMiddleware StaticSite::middleware() const {
  return [held = _held](const HttpRequest& request, const std::string&, std::shared_ptr<HttpResponse> response, std::function<void(bool)> next) {
    if (request.method() != verb::get && request.method() != verb::head) {
      response->set(field::allow, "GET, HEAD");
      write_error(response, status::method_not_allowed, "method_not_allowed", "the dashboard is read with GET");
      return next(false);
    }
    auto path = path_of(request);
    if (path.empty()) path = "index.html";
    if (const auto found = held->find(path); found != held->end()) {
      serve(found->second, request, *response, path.rfind("assets/", 0) == 0);
      return next(false);
    }
    if (names_a_file(path)) {
      write_error(response, status::not_found, "not_found", "no such file");
      return next(false);
    }
    serve(held->at("index.html"), request, *response, false);
    next(false);
  };
}

}  // namespace lugh::http
