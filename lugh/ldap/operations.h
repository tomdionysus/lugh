//
// Lugh - The Directory
//
// Copyright (C) 2026 Tom Cully <mail@tomcully.com>
// Licensed under the GNU GPLv3 - see <https://www.gnu.org/licenses/gpl-3.0.html>
//

#pragma once

#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "lugh/ldap/authz.h"
#include "lugh/ldap/messages.h"
#include "lugh/ldap/tree.h"

namespace lugh::ldap {

// One entry as it goes to the client.
struct SearchEntry {
  std::string dn;
  std::vector<Attribute> attributes;
};

struct SearchAnswer {
  Result result;
  std::vector<SearchEntry> entries;
  // The paged results control to answer with, when one was asked for.
  std::optional<PagedResults> paged;
};

// Each read operation over the tree, checked against the caller's scopes before the directory is
// asked (TODO/2026-11-04-ldap.md, "What a bind proves"). `bound` is nothing for an anonymous
// connection, which reads the rootDSE and nothing else. What may not be read is not there:
// noSuchObject, or absent from the results, never insufficientAccessRights, so the tree does not
// leak. Made with std::make_shared.
class Operations : public std::enable_shared_from_this<Operations> {
 public:
  struct Settings {
    // A page, or a search that asks for more, stops here.
    std::size_t most_results = 1000;
    // A client's time limit is honoured when it is shorter.
    std::chrono::seconds time_limit{30};
    std::string vendor_version;
    // What the rootDSE says is implemented, so a later step adds to these.
    std::vector<std::string> extensions;
    std::vector<std::string> controls;
  };

  Operations(std::shared_ptr<Tree> tree, Settings settings);

  void search(const std::optional<Bound>& bound, SearchRequest request, std::optional<PagedResults> paged, Executor executor, Done<SearchAnswer> done) const;
  void compare(const std::optional<Bound>& bound, CompareRequest request, Executor executor, Done<Result> done) const;

  // RFC 4532's answer: "dn:<the bound DN>", or empty for anonymous.
  static std::string who_am_i(const std::optional<Bound>& bound);

 private:
  Entry _root_dse() const;

  std::shared_ptr<Tree> _tree;
  Settings _settings;
};

// The attributes a search asked for, of an entry: `*` or nothing for the user attributes, `+` for
// the operational ones (RFC 3673), `1.1` for none, and names as they are.
std::vector<Attribute> attributes_for(const Entry& entry, const std::vector<std::string>& requested, bool types_only);

}  // namespace lugh::ldap
