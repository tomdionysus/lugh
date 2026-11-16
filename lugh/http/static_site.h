//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <cstddef>
#include <filesystem>
#include <map>
#include <memory>
#include <string>

#include "lugh/http/http_types.h"

namespace lugh::http {

// The dashboard (P7; docs/architecture.md, "Frontend"), served from memory. Its files are read
// once, at start, from `static.directory`, so no request reaches the disk, and nothing a request
// names can lead outside the directory: a path is looked up, never opened.
//
// A GET or HEAD for a file answers it, with its type, a strong ETag (304 on If-None-Match) and
// `nosniff`; Vite's fingerprinted `assets/` are cached for a year, everything else revalidated. A
// path that is no file and has no extension in its last segment is a route of the SPA, answered
// with `index.html`; one with an extension is a 404. Every HTML page carries a policy allowing only
// this origin, and each inline script by its hash. The routers sit in front of it, so `/api`,
// `/oauth2`, `/signin`, `/.well-known`, `/health` and `/ready` never reach it.
class StaticSite {
 public:
  struct Limits {
    std::size_t most_files = 4096;
    std::size_t most_bytes = 64u << 20;
  };

  // Path ("index.html", "assets/x-1a2b.js") to bytes. Must hold index.html.
  using Files = std::map<std::string, std::string>;

  // Throws std::invalid_argument without index.html.
  explicit StaticSite(Files files);

  // Every regular file under `directory`. Symbolic links and names beginning with '.' are left
  // out, as is anything inside them. Throws std::runtime_error naming the path for a directory
  // that cannot be read, one without index.html, or one past `limits`.
  static Files read(const std::filesystem::path& directory, Limits limits);
  static Files read(const std::filesystem::path& directory) { return read(directory, Limits{}); }

  HttpMiddleware middleware() const;

  std::size_t size() const { return _held->size(); }

  // The Content-Security-Policy an HTML page is served with: this origin only, and the inline
  // scripts of `html` by their SHA-256.
  static std::string page_policy(const std::string& html);

  struct File {
    std::string body;
    std::string type;
    std::string etag;
    std::string policy;
  };

 private:
  std::shared_ptr<const std::map<std::string, File>> _held;
};

}  // namespace lugh::http
